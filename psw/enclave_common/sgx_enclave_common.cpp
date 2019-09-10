/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "sgx_enclave_common.h"
#include "arch.h"
#include "edmm_utility.h"
#include "isgx_user.h"
#include "se_error_internal.h"
#include "se_map.h"
#include "se_thread.h"
#include "se_trace.h"
#include "uae_service_internal.h"
#include "util.h"
#include <map>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#define POINTER_TO_U64(A) ((__u64)((uintptr_t)(A)))


static std::map<void*, size_t> s_enclave_size;
static std::map<void*, bool> s_enclave_init;
static std::map<void*, sgx_attributes_t> s_secs_attr;
static se_mutex_t s_enclave_mutex;

typedef struct _mem_region_t {
    void* addr;
    size_t len;
    int prot;
} mem_region_t;

static std::map<void*, mem_region_t> s_enclave_mem_region;


static void __attribute__((constructor)) enclave_init(void)
{
    se_mutex_init(&s_enclave_mutex);
}

static void __attribute__((destructor)) enclave_fini(void)
{
    se_mutex_destroy(&s_enclave_mutex);
}

static uint32_t error_driver2api(int driver_error)
{
    uint32_t ret = ENCLAVE_UNEXPECTED;

    switch (driver_error) {
    case SGX_INVALID_SIG_STRUCT:
        ret = ENCLAVE_INVALID_SIG_STRUCT;
        break;
    case SGX_INVALID_SIGNATURE:
        ret = ENCLAVE_INVALID_SIGNATURE;
        break;
    case SGX_INVALID_ATTRIBUTE:
        ret = ENCLAVE_INVALID_ATTRIBUTE;
        break;
    case SGX_INVALID_MEASUREMENT:
        ret = ENCLAVE_INVALID_MEASUREMENT;
        break;
    case (int)SGX_POWER_LOST_ENCLAVE:
        ret = ENCLAVE_LOST;
        break;
    case SGX_UNMASKED_EVENT:
        ret = ENCLAVE_RETRY;
        break;
    case SGX_INVALID_PRIVILEGE:
        ret = ENCLAVE_NOT_AUTHORIZED;
        break;
    case (int)-ENOMEM:
        ret = ENCLAVE_OUT_OF_MEMORY;
        break;
    case (int)-EINVAL:
        ret = ENCLAVE_INVALID_PARAMETER;
        break;
    case (int)-EEXIST:
        ret = ENCLAVE_INVALID_ADDRESS;
        break;
    default:
        SE_TRACE(SE_TRACE_WARNING, "unexpected error %#x from driver, should be driver bug\n", driver_error);
        ret = ENCLAVE_UNEXPECTED;
        break;
    }

    return ret;
}

static uint32_t error_aesm2api(int aesm_error)
{
    uint32_t ret = ENCLAVE_UNEXPECTED;

    switch (aesm_error) {
    case SGX_ERROR_INVALID_PARAMETER:
        ret = ENCLAVE_INVALID_PARAMETER;
        break;
    case SGX_ERROR_SERVICE_UNAVAILABLE:
    case SGX_ERROR_NO_DEVICE:
        ret = ENCLAVE_NOT_SUPPORTED;
        break;
    case SGX_ERROR_OUT_OF_EPC:
        ret = ENCLAVE_DEVICE_NO_RESOURCES;
        break;
    case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
        ret = ENCLAVE_NOT_AUTHORIZED;
        break;
    case SGX_ERROR_SERVICE_TIMEOUT:
        ret = ENCLAVE_SERVICE_TIMEOUT;
        break;
    default:
        ret = ENCLAVE_UNEXPECTED;
        break;
    }

    return ret;
}

/* enclave_create()
 * Parameters:
 *      base_address [in, optional] - An optional preferred base address for the enclave.
 *      virtual_size [in] - The virtual address range of the enclave in bytes.
 *      initial_commit[in] - The amount of physical memory to reserve for the initial load of the enclave in bytes.
 *      type [in] - The architecture type of the enclave that you want to create.
 *      info [in] - A pointer to the architecture-specific information to use to create the enclave.
 *      info_size [in] - The length of the structure that the info parameter points to, in bytes.
 *      enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 * Return Value:
 *      If the function succeeds, the return value is the base address of the created enclave.
 *      If the function fails, the return value is NULL. The extended error information will be in the enclave_error parameter if used.
*/
extern "C" void* COMM_API enclave_create(
		se_file_handle_t hdevice,
		bool _is_kernel_driver,
    COMM_IN_OPT void* base_address,
    COMM_IN size_t virtual_size,
    COMM_IN size_t initial_commit,
    COMM_IN uint32_t type,
    COMM_IN const void* info,
    COMM_IN size_t info_size,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    UNUSED(initial_commit);

    if ((type != ENCLAVE_TYPE_SGX1 && type != ENCLAVE_TYPE_SGX2) || info == NULL) {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return NULL;
    }

    const enclave_create_sgx_t* enclave_create_sgx = (const enclave_create_sgx_t*)info;
    if (info_size == 0 || sizeof(*enclave_create_sgx) != info_size) {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return NULL;
    }

    secs_t* secs = (secs_t*)enclave_create_sgx->secs;
    SE_TRACE(SE_TRACE_DEBUG, "\n secs->attibutes.flags = %llx, secs->attributes.xfrm = %llx \n", secs->attributes.flags, secs->attributes.xfrm);


    void* enclave_base = mmap(base_address, virtual_size*2, PROT_NONE, MAP_SHARED, hdevice, 0);
    if (enclave_base == MAP_FAILED) {
        SE_TRACE(SE_TRACE_WARNING, "\ncreate enclave: mmap failed, errno = %d\n", errno);
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_OUT_OF_MEMORY;
        return NULL;
    }
	uint64_t aligned_addr = ((uint64_t)enclave_base + virtual_size - 1) & ~(virtual_size - 1);
	munmap(enclave_base, aligned_addr - (uint64_t)enclave_base);
	munmap((void *)(aligned_addr + virtual_size),(uint64_t)enclave_base + virtual_size - aligned_addr);
	enclave_base = (void*)aligned_addr;

    secs->base = (void*)aligned_addr;

    struct sgx_enclave_create param = { 0 };
    param.src = POINTER_TO_U64(secs);

    int ret = ioctl(hdevice, SGX_IOC_ENCLAVE_CREATE, &param);
    if (ret) {
        SE_TRACE(SE_TRACE_WARNING, "\nSGX_IOC_ENCLAVE_CREATE failed: errno = %d\n", errno);
        if (enclave_error != NULL)
            *enclave_error = error_driver2api(ret);
        return NULL;
    }
    se_mutex_lock(&s_enclave_mutex);

    s_enclave_size[enclave_base] = virtual_size;

    sgx_attributes_t secs_attr;
    memset(&secs_attr, 0, sizeof(sgx_attributes_t));
    memcpy(&secs_attr, &secs->attributes, sizeof(sgx_attributes_t));
    s_secs_attr[enclave_base] = secs_attr;

    s_enclave_mem_region[enclave_base].addr = 0;
    s_enclave_mem_region[enclave_base].len = 0;
    s_enclave_mem_region[enclave_base].prot = 0;

    se_mutex_unlock(&s_enclave_mutex);

    if (_is_kernel_driver == true && (secs->attributes.flags & SGX_FLAGS_PROVISION_KEY)) {
        if (-1 != access("/dev/sgx/provision", F_OK)) {
            int phdev = open("/dev/sgx/provision", O_RDWR);
            if (-1 == phdev) {
                if (enclave_error != NULL)
                    *enclave_error = ENCLAVE_NOT_AUTHORIZED;
                return NULL;
            }

            struct sgx_enclave_set_attribute attrp = { 0 };
            //attrp.addr = POINTER_TO_U64(enclave_base);// V22
            attrp.attribute_fd = phdev;

            if (0 != ioctl(hdevice, SGX_IOC_ENCLAVE_SET_ATTRIBUTE, &attrp)) {
                close(phdev);

                if (enclave_error != NULL)
                    *enclave_error = ENCLAVE_NOT_AUTHORIZED;
                return NULL;
            }

            close(phdev);
        }
    }

    if (enclave_error != NULL)
        *enclave_error = ENCLAVE_ERROR_SUCCESS;
    return enclave_base;
}

/* enclave_load_data()
 * Parameters:
 *      target_address [in] - The address in the enclave where you want to load the data.
 *      target_size [in] - The size of the range that you want to load in the enclave, in bytes. 
 *      source_buffer [in, optional] - An optional pointer to the data you want to load into the enclave.
 *      data_properties [in] - The properties of the pages you want to add to the enclave.
 *      enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 * Return Value:
 *      The return value is the number of bytes that was loaded into the enclave.
 *      If the number is different than target_size parameter an error occurred. The extended error information will be in the enclave_error parameter if used.
*/
extern "C" size_t COMM_API enclave_load_data(
		se_file_handle_t hdevice,
    COMM_IN void* target_address,
    COMM_IN size_t target_size,
    COMM_IN_OPT const void* source_buffer,
    COMM_IN uint32_t data_properties,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    if (target_address == NULL || ((uint64_t)(target_address) & ((1 << SE_PAGE_SHIFT) - 1)) != 0 || target_size < SE_PAGE_SIZE || target_size % SE_PAGE_SIZE != 0) {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        printf("enclave_load_data err 1\n");
        return 0;
    }

    uint8_t* source = (uint8_t*)source_buffer;
    if (source == NULL) {
        source = (uint8_t*)malloc(target_size);
        if (source == NULL) {
            if (enclave_error != NULL)
                *enclave_error = ENCLAVE_UNEXPECTED;
            printf("enclave_load_data err 2\n");
            return 0;
        }

        memset(source, 0, target_size);
    }

    sec_info_t sec_info;
    memset(&sec_info, 0, sizeof(sec_info_t));

    sec_info.flags = data_properties;
    if (!(sec_info.flags & ENCLAVE_PAGE_THREAD_CONTROL))
        sec_info.flags |= SI_FLAG_REG;
    if (sec_info.flags & ENCLAVE_PAGE_UNVALIDATED)
        sec_info.flags ^= ENCLAVE_PAGE_UNVALIDATED;
		// SHAY
		//if (sec_info.flags & SI_FLAG_R)
		//	sec_info.flags |= SI_FLAG_X;// V22 (need to sync this with what einit sees)

    size_t pages = target_size / SE_PAGE_SIZE;
    for (size_t i = 0; i < pages; i++) {
        struct sgx_enclave_add_page addp;
				memset(&addp,0,sizeof(addp));
        addp.addr = POINTER_TO_U64((uint8_t*)target_address + SE_PAGE_SIZE * i);
        addp.src = POINTER_TO_U64(source + SE_PAGE_SIZE * i);
        addp.secinfo = POINTER_TO_U64(&sec_info);
        if (!(data_properties & ENCLAVE_PAGE_UNVALIDATED))
            addp.mrmask |= 0xFFFF;

				// TBD - should allocate it inside enclave object and re-use it instead of allocating each call
				void* src_aligned_ptr = malloc(2*SE_PAGE_SIZE);
        if (src_aligned_ptr == NULL) {
            if (enclave_error != NULL)
                *enclave_error = ENCLAVE_UNEXPECTED;
            printf("enclave_load_data err 3\n");
            return 0;
        }
				uint64_t aligned_page = ((uint64_t)src_aligned_ptr + SE_PAGE_SIZE - 1) & ~(SE_PAGE_SIZE - 1);
				memcpy((void*)aligned_page,(void*)addp.src,SE_PAGE_SIZE);
				addp.src = (uint64_t)aligned_page;
        int ret = ioctl(hdevice, SGX_IOC_ENCLAVE_ADD_PAGE, &addp);
        free(src_aligned_ptr);

        if (ret) {
            SE_TRACE(SE_TRACE_WARNING, "\nAdd Page - %p to %p... FAIL\n", source, target_address);
			printf("SHAY EADD failed ret=%d addr=0x%lx src=0x%lx perm=0x%lx\n",ret,(unsigned long) addp.addr,(unsigned long)addp.src ,(unsigned long) sec_info.flags);
            if (source_buffer == NULL && source != NULL)
                free(source);

            if (enclave_error != NULL)
                *enclave_error = error_driver2api(ret);
            return SE_PAGE_SIZE * i;
        }
    }

    if (source_buffer == NULL && source != NULL)
        free(source);

    int prot = (int)(sec_info.flags & SI_MASK_MEM_ATTRIBUTE);
    // find the enclave base
    void* enclave_base = NULL;

    for (auto rec : s_enclave_size) {
        if ((uint64_t)target_address >= (uint64_t)rec.first && (uint64_t)target_address < (uint64_t)rec.first + (uint64_t)rec.second) {
            enclave_base = (void*)rec.first;
            break;
        }
    }

    if (enclave_base == NULL) {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_ENCLAVE;

		printf("enclave_load_data err 5\n");
        return 0;
    }

    se_mutex_lock(&s_enclave_mutex);
    auto enclave_mem_region = &s_enclave_mem_region[enclave_base];
    se_mutex_unlock(&s_enclave_mutex);

    void* next_page = (void*)((uint64_t)enclave_mem_region->addr + (uint64_t)enclave_mem_region->len);
    if ((enclave_mem_region->prot != prot) || (target_address != next_page)) {
        if (enclave_mem_region->addr != 0) {
            //the new load of enclave data either has a different protection or is not contiguous with the last one, mprotect the range stored in memory region structure
            if (0 != mprotect(enclave_mem_region->addr, enclave_mem_region->len, enclave_mem_region->prot)) {
                if (enclave_error != NULL)
                    *enclave_error = ENCLAVE_UNEXPECTED;
		printf("enclave_load_data err 6\n");
                return 0;
            }
        }
        //record the current load of enclave data in the memory region structure
        enclave_mem_region->addr = target_address;
        enclave_mem_region->len = target_size;
        enclave_mem_region->prot = prot;
    } else {
        //this load of enclave data is extending the memory region
        enclave_mem_region->len += target_size;
    }

    if (enclave_error != NULL)
        *enclave_error = ENCLAVE_ERROR_SUCCESS;
    return target_size;
}

/* enclave_initialize()
 * Parameters:
 *      base_address [in] - The enclave base address as returned from the enclave_create API.
 *      info [in] - A pointer to the architecture-specific information to use to initialize the enclave. 
 *      info_size [in] - The length of the structure that the info parameter points to, in bytes.
 *      enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 * Return Value:
 *      non-zero - The function succeeds.
 *      zero - The function fails and the extended error information will be in the enclave_error parameter if used.
*/
extern "C" bool COMM_API enclave_initialize(
		se_file_handle_t hdevice,
		bool _is_kernel_driver,
    COMM_IN void* base_address,
    COMM_IN const void* info,
    COMM_IN size_t info_size,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    if (base_address == NULL || info == NULL) {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return false;
    }

    const enclave_init_sgx_t* enclave_init_sgx = (const enclave_init_sgx_t*)info;
    if (info_size == 0 || sizeof(*enclave_init_sgx) != info_size) {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return false;
    }

    //mprotect the last region
    se_mutex_lock(&s_enclave_mutex);
    auto enclave_mem_region = &s_enclave_mem_region[base_address];
    se_mutex_unlock(&s_enclave_mutex);
    if (enclave_mem_region->addr != 0) {
        //the new load of enclave data either has a different protection or is not contiguous with the last one, mprotect the range stored in memory region structure
        if (0 != mprotect(enclave_mem_region->addr, enclave_mem_region->len, enclave_mem_region->prot)) {
            if (enclave_error != NULL)
                *enclave_error = ENCLAVE_UNEXPECTED;
            return 0;
        }
        //record the current load of enclave data in the memory region structure
        enclave_mem_region->addr = 0; //just in case we need to call enclave_initialize twice
    }

    int ret = 0;
    if (_is_kernel_driver == false) {
        se_mutex_lock(&s_enclave_mutex);
        std::map<void*, sgx_attributes_t>::iterator it = s_secs_attr.find(base_address);
        if (it == s_secs_attr.end()) {
            se_mutex_unlock(&s_enclave_mutex);
            if (enclave_error != NULL)
                *enclave_error = ENCLAVE_INVALID_PARAMETER;
            return false;
        }
        se_mutex_unlock(&s_enclave_mutex);

        sgx_launch_token_t launch_token;
        memset(launch_token, 0, sizeof(sgx_launch_token_t));

        enclave_css_t* enclave_css = (enclave_css_t*)enclave_init_sgx->sigstruct;
        if (0 == enclave_css->header.hw_version) {
            sgx_status_t status = get_launch_token(enclave_css, &it->second, &launch_token);
            if (status != SGX_SUCCESS) {
                if (enclave_error != NULL)
                    *enclave_error = error_aesm2api(status);
                return false;
            }
        }

        struct sgx_enclave_init initp = { 0, 0, 0 };
        initp.addr = POINTER_TO_U64(base_address);
        initp.sigstruct = POINTER_TO_U64(enclave_css);
        initp.einittoken = POINTER_TO_U64(&launch_token);

        ret = ioctl(hdevice, SGX_IOC_ENCLAVE_INIT, &initp);
    } else {
        struct sgx_enclave_init_in_kernel initp = { 0 };
        initp.sigstruct = POINTER_TO_U64(enclave_init_sgx->sigstruct);

        ret = ioctl(hdevice, SGX_IOC_ENCLAVE_INIT_IN_KERNEL, &initp);
    }

    if (ret) {
        SE_TRACE(SE_TRACE_WARNING, "\nSGX_IOC_ENCLAVE_INIT failed error = %d\n", ret);
        if (enclave_error != NULL)
            *enclave_error = error_driver2api(ret);
        return false;
    }

    se_mutex_lock(&s_enclave_mutex);
    std::map<void*, bool>::iterator it = s_enclave_init.find(base_address);
    if (it != s_enclave_init.end() && it->second) {
        se_mutex_unlock(&s_enclave_mutex);
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_ALREADY_INITIALIZED;
        return false;
    }

    s_enclave_init[base_address] = true;
    se_mutex_unlock(&s_enclave_mutex);

    if (enclave_error != NULL)
        *enclave_error = ENCLAVE_ERROR_SUCCESS;
    return true;
}

/* enclave_delete()
 * Parameters:
 *      base_address [in] - The enclave base address as returned from the enclave_create API.
 *      enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 * Return Value:
 *      non-zero - The function succeeds.
 *      zero - The function fails and the extended error information will be in the enclave_error parameter if used.
*/
extern "C" bool COMM_API enclave_delete(
    COMM_IN void* base_address,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    if (base_address == NULL) {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return false;
    }

    se_mutex_lock(&s_enclave_mutex);
    std::map<void*, size_t>::iterator it = s_enclave_size.find(base_address);
    if (it == s_enclave_size.end()) {
        se_mutex_unlock(&s_enclave_mutex);
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return false;
    }

    s_enclave_size.erase(base_address);
    s_enclave_init.erase(base_address);
    s_enclave_mem_region.erase(base_address);
    se_mutex_unlock(&s_enclave_mutex);

    if (0 != munmap(base_address, it->second)) {
        SE_TRACE(SE_TRACE_WARNING, "delete SGX enclave failed, error = %d\n", errno);
        if (enclave_error != NULL) {
            if (errno == EINVAL)
                *enclave_error = ENCLAVE_INVALID_PARAMETER;
            else
                *enclave_error = ENCLAVE_UNEXPECTED;
        }
        return false;
    }

    if (enclave_error != NULL)
        *enclave_error = ENCLAVE_ERROR_SUCCESS;
    return true;
}

/* enclave_get_information()
 * Parameters:
 * base_address [in] - The enclave base address as returned from the enclave_create API.
 * info_type[in] - Identifies the type of information requested. initialized.
 * output_info[out] - Pointer to information returned by the API
 * output_info_size[in, out] - Size of the output_info buffer, in bytes.  If the API succeeds, then this will return the number of bytes returned in output_info.  If the API fails with, ENCLAVE_INVALID_SIZE, then this will return the required size
 * enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 */
bool COMM_API enclave_get_information(
    COMM_IN void* base_address,
    COMM_IN uint32_t info_type,
    COMM_OUT void* output_info,
    COMM_IN_OUT size_t* output_info_size,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    UNUSED(base_address);
    UNUSED(info_type);
    UNUSED(output_info);
    UNUSED(output_info_size);

    if (enclave_error)
        *enclave_error = ENCLAVE_NOT_SUPPORTED;

    return false;
}

/* enclave_set_information
 * Parameters
 * base_address [in] - The enclave base address as returned from the enclave_create API.
 * info_type[in] - Identifies the type of information requested. not been initialized.
 * input_info[in] - Pointer to information provided to the API
 * input_info_size[in] - Size of the information, in bytes, provided in input_info from the API.
 * enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 */
bool COMM_API enclave_set_information(
    COMM_IN void* base_address,
    COMM_IN uint32_t info_type,
    COMM_IN void* input_info,
    COMM_IN size_t input_info_size,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    UNUSED(base_address);
    UNUSED(info_type);
    UNUSED(input_info);
    UNUSED(input_info_size);

    if (enclave_error)
        *enclave_error = ENCLAVE_NOT_SUPPORTED;

    return false;
}
