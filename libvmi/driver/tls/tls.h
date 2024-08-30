#ifndef TLS_DRIVER_H
#define TLS_DRIVER_H

status_t tls_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);
    
status_t tls_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);
    
void tls_destroy(
    vmi_instance_t vmi);
    
status_t tls_get_name(
    vmi_instance_t vmi,
    char **name);
    
void tls_set_name(
    vmi_instance_t vmi,
    const char *name);
    
status_t tls_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address);
    
status_t tls_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu);
    
status_t tls_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);
    
status_t tls_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu);
    
status_t tls_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);
    
void *tls_read_page(
    vmi_instance_t vmi,
    addr_t page);
    
status_t tls_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length);
    
int tls_is_pv(
    vmi_instance_t vmi);
    
status_t tls_pause_vm(
    vmi_instance_t vmi);
    
status_t tls_resume_vm(
    vmi_instance_t vmi);

status_t
tls_test(
    uint64_t domainid,
    const char *name,
    uint64_t init_flags,
    vmi_init_data_t *init_data);

static inline status_t
driver_tls_setup(vmi_instance_t vmi)
{
    driver_interface_t driver = {0};
    driver.initialized = true;
    driver.init_ptr = &tls_init;
    driver.init_vmi_ptr = &tls_init_vmi;
    driver.destroy_ptr = &tls_destroy;
    driver.get_name_ptr = &tls_get_name;
    driver.set_name_ptr = &tls_set_name;
    driver.get_memsize_ptr = &tls_get_memsize;
    driver.get_vcpureg_ptr = &tls_get_vcpureg;
    driver.get_vcpuregs_ptr = &tls_get_vcpuregs;
    driver.set_vcpureg_ptr = &tls_set_vcpureg;
    driver.set_vcpuregs_ptr = &tls_set_vcpuregs;
    driver.read_page_ptr = &tls_read_page;
    driver.write_ptr = &tls_write;
    driver.is_pv_ptr = &tls_is_pv;
    driver.pause_vm_ptr = &tls_pause_vm;
    driver.resume_vm_ptr = &tls_resume_vm;
    vmi->driver = driver;
    return VMI_SUCCESS;
}

struct SevSnpAttestationReport {
    uint32_t version;
    uint32_t guest_svn;
    uint64_t policy;
    uint8_t family_id[16];
    uint8_t image_id[16];
    uint32_t vmpl;
    uint32_t signature_algo;
    uint64_t platform_version;
    uint64_t platform_info;
    uint32_t flags;
    uint32_t reserved0;
    uint8_t report_data[64];
    uint8_t measurement[48];
    uint8_t host_data[32];
    uint8_t id_key_digest[48];
    uint8_t author_key_digest[48];
    uint8_t report_id[32];
    uint8_t report_id_ma[32];
    uint64_t reported_tcb;
    uint8_t reserved1[24];
    uint8_t chip_id[64];
    uint8_t reserved2[192];
    uint8_t signature[512];
};

#endif // TLS_DRIVER_H
