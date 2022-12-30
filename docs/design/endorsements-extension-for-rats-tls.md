# [RFC] Implement endorsements extension for rats-tls

## Description of the feature

The purpose of this draft is to introduce endorsements support to rats-tls as part of the implementation of DICE extensions.

Implementing an endorsements extension requires changes to the rats-tls attester/verifier driver API, since rats-tls did not previously provide support for "how to include endorsements in certificates". This draft also illustrates a specific implementation of the Intel SGX/TDX ECDSA as an example.

## Background

The term Collateral is the SGX term for endorsements. In this document, the terms collateral and endorsements are interchangeable.

### Status of rats-tls

The verifier driver code for rats-tls does not take into account the collection of collaterals.

Take sgx-ecdsa driver as an example, the `p_quote_collateral` parameter of `sgx_qv_verify_quote()` is NULL, which means that the underlying library of SGX DCAP will get the collaterals by accessing PCCS and finish the verification of the Quote. The whole process is transparent to the sgx-ecdsa driver and the sgx-ecdsa driver cannot get the collaterals and further embed them into the certificate.


```c
    // https://github.com/inclavare-containers/rats-tls/blob/47d42af90ffa4a20f1b8faf682d90a6c08df0381/src/verifiers/sgx-ecdsa/verify_evidence.c#L63
    dcap_ret = sgx_qv_verify_quote(pquote, (uint32_t)quote_size, NULL /* Here */,
                       current_time, &collateral_expiration_status,
                       &quote_verification_result, qve_report_info,
                       supplemental_data_size, p_supplemental_data);
```

### Status of OpenEnclave

The OpenEnclave has implemented optional parameters that allow attester to return Quote with endorsements.

- https://github.com/openenclave/openenclave/blob/6fb33c99f73a63e219987fbee6e81ece45a44610/enclave/sgx/attester.c#L183-L196
- https://github.com/openenclave/openenclave/blob/95062ffefdbcbd6d9369ea9b0ba0ad4f86768654/host/sgx/sgxquote.c#L1174

Hence rats-tls should learn from this design idea.

### The definition of collateral data structure in SGX/TDX

SGX gives the definition of the collateral data structure in the header file: `sgx_ql_qve_collateral_t` for SGX and `tdx_ql_qve_collateral_t` for TDX. In the current code, the two are consistent, and the latter is actually a `typedef` of the former.

https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/08b9447694bb81c66e1988be4b998b936f002387/QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h#LL200C28-L200C28

Take `sgx_ql_qve_collateral_t` as an example.

```c
typedef struct _sgx_ql_qve_collateral_t
{
    union {
        uint32_t version;           ///< 'version' is the backward compatible legacy representation
        struct {                    ///< For PCS V1 and V2 APIs, the major_version = 1 and minor_version = 0 and
            uint16_t major_version; ///< the CRLs will be formatted in PEM. For PCS V3 APIs, the major_version = 3 and the
            uint16_t minor_version; ///< minor_version can be either 0 or 1. minor_verion of 0 indicates the CRL’s are formatted
                                    ///< in Base16 encoded DER.  A minor version of 1 indicates the CRL’s are formatted in raw binary DER.
        };
    };
    uint32_t tee_type;                     ///<  0x00000000: SGX or 0x00000081: TDX
    char *pck_crl_issuer_chain;
    uint32_t pck_crl_issuer_chain_size;
    char *root_ca_crl;                     /// Root CA CRL
    uint32_t root_ca_crl_size;
    char *pck_crl;                         /// PCK Cert CRL
    uint32_t pck_crl_size;
    char *tcb_info_issuer_chain;
    uint32_t tcb_info_issuer_chain_size;
    char *tcb_info;                        /// TCB Info structure
    uint32_t tcb_info_size;
    char *qe_identity_issuer_chain;
    uint32_t qe_identity_issuer_chain_size;
    char *qe_identity;                     /// QE Identity Structure
    uint32_t qe_identity_size;
} sgx_ql_qve_collateral_t;
```

As we can see, `sgx_ql_qve_collateral_t` is an internally defined data structure, not a flat blob of data like Quote.

Data structures like this that contain internal pointers and length fields cannot be used directly for serialization and data exchange.

### Get collateral in SGX/TDX

Intel DCAP provides two APIs. Take SGX as an example.

- DCAP's Quote Provider Library provides the API `sgx_ql_get_quote_verification_collateral()` to get collateral.

    ```c
    quote3_error_t sgx_ql_get_quote_verification_collateral(
                                            const uint8_t *fmspc,
                                            const uint16_t fmspc_size,
                                            const char *pck_ca,
                                            sgx_ql_qve_collateral_t **pp_quote_collateral);
    ```
    - The collateral collected by the underlying library of DCAP is returned via the `pp_quote_collateral` parameter. Note that the returned pointer needs to be released using the `sgx_ql_free_quote_verification_collateral()` function.
    - `fmspc` is the abbreviation of `Family-Model-Stepping-Platform-CustomSKU`. Its original meaning is: Description of the processor package or platform instance including its Family, Model, Stepping, Platform Type, and Customized SKU (if applies).
        - This value can be obtained from the PCK certificate included in the quote.

    > OpenEnclave uses this API to get collateral

- Another one is `tee_qv_get_collateral()` provided by DCAP Quote Verification Library. It accepts a complete quote and returns a pointer to the collateral.

    ```c
    quote3_error_t tee_qv_get_collateral(const uint8_t *p_quote,
                                            uint32_t quote_size,
                                            uint8_t **pp_quote_collateral,
                                            uint32_t *p_collateral_size);
    ```
    - Note that the returned collateral pointer needs to be freed using the `tee_qv_free_collateral()` function.
    - According to the DCAP documentation, the function returns a pointer "which holds the quote verification collateral buffer". But by reading the source code, I found that the function actually calls `sgx_ql_get_quote_verification_collateral()`. And the `pp_quote_collateral` it returns is actually of type `sgx_ql_qve_collateral_t` or `tdx_ql_qve_collateral_t` ~~ appended with the data pointed to by each of the fields ~~. The `p_collateral_size` is just the sum of the "size of the structure and the length of each pointer", so this field becomes useless.
    - `pp_quote_collateral` is not a flat blob and cannot be used for serialization and data exchange.
    - This function was introduced in Intel(R) SGX DCAP 1.15 released on Nov 24, 2022. Therefore using this function may make us incompatible with older SGX DCAP versions.

### Interoperable RA-TLS proposal

In the [Interoperable RA-TLS](https://github.com/CCC-Attestation/interoperable-ra-tls) proposal, the data format of the endorsements extension is described as follows.

```md
# SGX / TDX Endorsement Data Format

The optional endorsements extension for SGX / TDX is a byte string of definite-length encoded tagged CBOR array with 9 entries: `<tag1>([h'<VERSION>', h'<TCB_INFO>', h'<TCB_ISSUER_CHAIN>', h'<CRL_PCK_CERT>', h'<CRL_PCK_PROC_CA>', h'<CRL_ISSUER_CHAIN_PCK_CERT>', h'<QE_ID_INFO>', h'<QE_ID_ISSUER_CHAIN>', h'<CREATION_DATETIME>'])`
- Index of each entry is defined in OE SDK `oe_sgx_endorsements_fields_t`, in [bits/attestation.h](https://github.com/openenclave/openenclave/blob/master/include/openenclave/bits/attestation.h)
- Only supported for SGX / TDX ECDSA quote
```
Where `<tagX>` is used to distinguish between different tee types. The above description of the endorsements data format is referenced from the OpenEnclave implementation. The fields in it are copies of the fields in `sgx_ql_qve_collateral_t`.


## rats-tls Change List

Based on the above analysis, rats-tls requires the following changes to support SGX / TDX Endorsement extensions.

1. Add a TEE-independent structure `attestation_endorsement_t` to represent the endorsement.

    ```c
    // SGX specific collateral structure, for internal use only
    typedef struct {
        uint32_t version;
        char *pck_crl_issuer_chain;
        uint32_t pck_crl_issuer_chain_size;
        char *root_ca_crl;
        uint32_t root_ca_crl_size;
        char *pck_crl;
        uint32_t pck_crl_size;
        char *tcb_info_issuer_chain;
        uint32_t tcb_info_issuer_chain_size;
        char *tcb_info;
        uint32_t tcb_info_size;
        char *qe_identity_issuer_chain;
        uint32_t qe_identity_issuer_chain_size;
        char *qe_identity;
        uint32_t qe_identity_size;
    } sgx_ecdsa_attestation_collateral_t;

    typedef sgx_ecdsa_attestation_collateral_t tdx_ecdsa_attestation_collateral_t;

    typedef struct {
        union {
            sgx_ecdsa_attestation_collateral_t ecdsa; /* SGX / TDX ECDSA */
            // ... (collateral for other TEEs)
        };
    } attestation_endorsement_t;
    ```

    - The definition of this structure is almost the same as `sgx_ql_qve_collateral_t` in the sgx header file. We do not use `sgx_ql_qve_collateral_t` directly in order to avoid introducing direct dependencies on sgx headers or function symbols in code other than attester/verifier.
    - Unlike the existing `attestation_evidence_t`, the fields in `attestation_endorsement_t` are dynamically allocated for the following reasons.
        - There are too many fields and there is no limit to the maximum length of each field for static allocation.
    - The advantage of exposing the fields in it is that it is convenient for other APIs in the upper layer, such as JSON API (conversion to json structure) and DICE API (conversion to cbor structure).

2. modify attester API

    ```c
    typedef struct {
    // ...s
        enclave_attester_err_t (*collect_endorsement)(enclave_attester_ctx_t *ctx,
                            const attestation_evidence_t *evidence, attestation_endorsement_t *endorsements);
    // ...
    } enclave_attester_opts_t;
    ```

    Add a `collect_endorsement()` function to get the endorsement from this attester.

    - The attester driver can parse the `evidence` and get information from it to assist in the generation of the endorsement.
    - The upper-level code can flexibly control whether the endorsement should be generated at the attester side or not.
    - Note that the fields in `attestation_endorsement_t` are allocated and filled by the attester by calling `malloc()`, and the upper layer is responsible for freeing them by calling `free()`.

3. modify verifier API
    ```c
    typedef struct {
        // ...
        enclave_verifier_err_t (*verify_evidence)(enclave_verifier_ctx_t *ctx,
                            attestation_evidence_t *evidence, uint8_t *hash,
                            uint32_t hash_len, attestation_endorsement_t *endorsements /* optional */ );
        // enclave_verifier_err_t (*collect_collateral)(enclave_verifier_ctx_t *ctx);
        // ...
    } enclave_verifier_opts_t;
    ```
    Remove unused `collect_collateral()` function and add `endorsement` parameter to `verify_evidence()`.

4. add an option for users to control whether endorsements are provided by the attester side
   
   Add a new flag `RATS_TLS_CONF_FLAGS_PROVIDE_ENDORSEMENTS` to indicate whether further calls to `collect_endorsement()` are needed to get endorsements after calling `collect_evidence` of attester.
    ```c
    #define RATS_TLS_CONF_FLAGS_MUTUAL (1UL << 0)
    #define RATS_TLS_CONF_FLAGS_SERVER (RATS_TLS_CONF_FLAGS_MUTUAL << 1)
    
    /* Add this */
    #define RATS_TLS_CONF_FLAGS_PROVIDE_ENDORSEMENTS (RATS_TLS_CONF_FLAGS_SERVER << 1)
    
    /* Internal flags */
    #define RATS_TLS_CONF_FLAGS_ATTESTER_ENFORCED (1UL << RATS_TLS_CONF_FLAGS_PRIVATE_MASK_SHIFT)
    #define RATS_TLS_CONF_FLAGS_VERIFIER_ENFORCED 
    ```

## Implementation: sgx-ecdsa as an example

1. The attester side implementation
    1. rtls_core_generate_certificate.c
        1. Allocate `attestation_endorsement_t` structure on the stack, and call `attester->opts->collect_endorsement(ctx, evidence, endorsement)` to get collateral data.
        2. Call the DICE function to encode `endorsement` into an `endorsements_buffer` in cbor format. This step will not be performed if `collect_endorsement()` fails.
        3. Free the fields in `attestation_endorsement_t`.
        4. Use `endorsements_buffer` as the content of the endorsements extension in the certificate.
    2. Implementation of sgx-ecdsa's `collect_endorsement()`
        1. Use `tee_qv_get_collateral()` (mentioned above) in combination with the quote content to get the collateral data, and then cast it into the `sgx_ql_qve_collateral_t` type.
        3. Read the corresponding fields from it and copy them to the incoming `attestation_endorsement_t* endorsement` parameter.
        4. Use `tee_qv_free_collateral()` to free `pp_quote_collateral`.
2. The verifier side implementation
    1. Implementation of un_negotiate.c
        1. Parse out the endorsements_buffer (in cbor format) from the endorsements extension of the certificate.
        2. Allocate the `attestation_endorsement_t` structure on the stack, call the DICE function to parse the endorsements_buffer and fill the `attestation_endorsement_t` structure.
        3. Call `verifier->opts->verify_evidence(ctx, evidence, hash, hash_len, endorsement)` to verify the evidence.
        4. Release fields in `attestation_endorsement_t`.
    2. Implementation of sgx-ecdsa `verify_evidence()`
        1. Construct `sgx_ql_qve_collateral_t` from the incoming `attestation_endorsementl_t* endorsement` parameter and pass it as an argument to `sgx_qv_verify_quote()`.

The DICE functions are responsible for serializing/deserializing the endorsements into cbor format, which will be implemented following the Interoperable RA-TLS proposal.

### Implementation in SGX compilation mode

1. Implementation of sgx-ecdsa `collect_endorsement()`

    A new ocall `ocall_tee_qv_get_collateral()` is needed since it is unable to call `tee_qv_get_collateral()` directly in the sgx environment.

    However, since `sgx_ql_qve_collateral_t` is not flat data, there are the following options in passing it from untrusted-app to enclave.
        
    1. Split it into two ocalls, `ocall_tee_qv_get_collateral_size()` and `ocall_tee_qv_get_collateral()`.
        ```c
        enclave_attester_err_t ocall_tee_qv_get_collateral_size([in, size=quote_size] const uint8_t *pquote,
                                                            uint32_t quote_size,
                                                            [out] uint32_t* p_pck_crl_issuer_chain_size,
                                                            [out] uint32_t* p_root_ca_crl_size,
                                                            [out] uint32_t* p_pck_crl_size,
                                                            [out] uint32_t* p_tcb_info_issuer_chain_size,
                                                            [out] uint32_t* p_tcb_info_size,
                                                            [out] uint32_t* p_qe_identity_issuer_chain_size,
                                                            [out] uint32_t* p_qe_identity_size);
        enclave_attester_err_t ocall_tee_qv_get_collateral_size([in, size=quote_size] const uint8_t *pquote,
                                                            uint32_t quote_size,
                                                            [out] uint32_t * collateral_version,
                                                            [out, size=collateral_pck_crl_issuer_chain_size] char * collateral_pck_crl_issuer_chain,
                                                            uint32_t collateral_pck_crl_issuer_chain_size,
                                                            [out, size=collateral_root_ca_crl_size] char * collateral_root_ca_crl,
                                                            uint32_t collateral_root_ca_crl_size,
                                                            [out, size=collateral_pck_crl_size] char * collateral_pck_crl,
                                                            uint32_t collateral_pck_crl_size,
                                                            [out, size=collateral_tcb_info_issuer_chain_size] char * collateral_tcb_info_issuer_chain,
                                                            uint32_t collateral_tcb_info_issuer_chain_size,
                                                            [out, size=collateral_tcb_info_size] char * collateral_tcb_info,
                                                            uint32_t collateral_tcb_info_size,
                                                            [out, size=collateral_qe_identity_issuer_chain_size] char * collateral_qe_identity_issuer_chain,
                                                            uint32_t collateral_qe_identity_issuer_chain_size,
                                                            [out, size=collateral_qe_identity_size] char * collateral_qe_identity,
                                                            uint32_t collateral_qe_identity_size);
        ```
        - The first ocall exists because the size of the buffer of a pointer marked as type `[out]` in ocall needs to be determined in advance by the caller (enclave) side.
        - This solution is safer because all the bounds checking is done by edger8r.
        
        Another optimized version of this solution is
        ```c
        enclave_attester_err_t ocall_tee_qv_get_collateral_size([in, size=quote_size] const uint8_t *pquote,
                                                            uint32_t quote_size,
                                                            [out] uint8_t **pp_quote_collateral_untrusted /* diff */,
                                                            [out] uint32_t* p_pck_crl_issuer_chain_size,
                                                            [out] uint32_t* p_root_ca_crl_size,
                                                            [out] uint32_t* p_pck_crl_size,
                                                            [out] uint32_t* p_tcb_info_issuer_chain_size,
                                                            [out] uint32_t* p_tcb_info_size,
                                                            [out] uint32_t* p_qe_identity_issuer_chain_size,
                                                            [out] uint32_t* p_qe_identity_size);
        enclave_attester_err_t ocall_tee_qv_get_collateral_size([in, size=quote_size] const uint8_t *pquote,
                                                            uint32_t quote_size,
                                                            [user_check] uint8_t *p_quote_collateral_untrusted  /* diff */,
                                                            [out] uint32_t * collateral_version,
                                                            [out, size=collateral_pck_crl_issuer_chain_size] char * collateral_pck_crl_issuer_chain,
                                                            uint32_t collateral_pck_crl_issuer_chain_size,
                                                            [out, size=collateral_root_ca_crl_size] char * collateral_root_ca_crl,
                                                            uint32_t collateral_root_ca_crl_size,
                                                            [out, size=collateral_pck_crl_size] char * collateral_pck_crl,
                                                            uint32_t collateral_pck_crl_size,
                                                            [out, size=collateral_tcb_info_issuer_chain_size] char * collateral_tcb_info_issuer_chain,
                                                            uint32_t collateral_tcb_info_issuer_chain_size,
                                                            [out, size=collateral_tcb_info_size] char * collateral_tcb_info,
                                                            uint32_t collateral_tcb_info_size,
                                                            [out, size=collateral_qe_identity_issuer_chain_size] char * collateral_qe_identity_issuer_chain,
                                                            uint32_t collateral_qe_identity_issuer_chain_size,
                                                            [out, size=collateral_qe_identity_size] char * collateral_qe_identity,
                                                            uint32_t collateral_qe_identity_size);
        ```
        - The advantage is that the collateral only needs to be generated only once

    2. Structure Deep Copy (not suitable)
        - Structure Deep Copy is a method that marks `[count]` or `[size]` attributes for pointer members of struct, and deep copy is done automatically during ocall. But this scheme only supports `[in]` `[in, out]` two directions, which is not suitable for us.

    3. Access untrusted-app memory directly in enclave
        ```c
        enclave_attester_err_t ocall_tee_qv_get_collateral([in, size=quote_size] const uint8_t *pquote,
                                                            uint32_t quote_size,
                                                            [out] uint8_t **pp_quote_collateral_untrusted);
        enclave_attester_err_t ocall_tee_qv_free_collateral([user_check] uint8_t *p_quote_collateral_untrusted);
        ```
        - This solution is actually similar to solution 1, but requires more care to avoid exposing the data in enclave memory. However, it is expected to be cleaner and have better performance (because of the reduced number of memory copies). 
            - In a typical experiment, the size of the endorsements was found to be 12525 bytes.

        > This is the current code implementation

2. Implementation of sgx-ecdsa `verify_evidence()`

    1. We have to modify the existing `ocall_ecdsa_verify_evidence()`, to passing endorsement fileds from evidence to untrust-app.
        ```c
        enclave_verifier_err_t ocall_ecdsa_verify_evidence([user_check] enclave_verifier_ctx_t *ctx,
                                                            sgx_enclave_id_t enclave_id,
                                                            [in, string] const char *name,
                                                            [in, size=quote_size] sgx_quote3_t *pquote,
                                                            uint32_t quote_size,
                                                            uint32_t collateral_version,
                                                            [in, size=collateral_pck_crl_issuer_chain_size] char * collateral_pck_crl_issuer_chain,
                                                            uint32_t collateral_pck_crl_issuer_chain_size,
                                                            [in, size=collateral_root_ca_crl_size] char * collateral_root_ca_crl,
                                                            uint32_t collateral_root_ca_crl_size,
                                                            [in, size=collateral_pck_crl_size] char * collateral_pck_crl,
                                                            uint32_t collateral_pck_crl_size,
                                                            [in, size=collateral_tcb_info_issuer_chain_size] char * collateral_tcb_info_issuer_chain,
                                                            uint32_t collateral_tcb_info_issuer_chain_size,
                                                            [in, size=collateral_tcb_info_size] char * collateral_tcb_info,
                                                            uint32_t collateral_tcb_info_size,
                                                            [in, size=collateral_qe_identity_issuer_chain_size] char * collateral_qe_identity_issuer_chain,
                                                            uint32_t collateral_qe_identity_issuer_chain_size,
                                                            [in, size=collateral_qe_identity_size] char * collateral_qe_identity,
                                                            uint32_t collateral_qe_identity_size)
            allow(ecall_get_target_info, sgx_tvl_verify_qve_report_and_identity);
        ```

### Implementation in Host compilation mode

1. Implementation of sgx-ecdsa `collect_endorsement()`

   Not considered, because there is no sgx-ecdsa attester in host mode.

2. Implementation of sgx-ecdsa `verify_evidence()`

    Can use `sgx_qv_verify_quote()` directly.

### Implementation in Occlum compilation mode

1. Implementation of sgx-ecdsa `collect_endorsement()`

    As of now (2022/12/30) Occlum does not provide a way to obtain endorsements.

    https://github.com/occlum/occlum/blob/d7d485de276524d573a7e46951d80bdfc6625bfa/tools/toolchains/dcap_lib/src/occlum_dcap.rs#L4-L7

2. Implementation of sgx-ecdsa `verify_evidence()`

    As of now (2022/12/30) Occlum does not provide a way pass endorsements during the validation of the evidence.

    Some of the most relevant code snippets we found:
    - https://github.com/occlum/occlum/blob/b3e2d6c873612dfea9a25b4cdc4dd11753214a1a/src/pal/src/ocalls/attestation.c#L129-L139
    - https://github.com/occlum/occlum/blob/b3e2d6c873612dfea9a25b4cdc4dd11753214a1a/src/libos/src/util/sgx/dcap/quote_verifier.rs#L56-L67

    
    > Question: maybe it can be done by bypassing Occlum and calling qvl directly?

## Implementation for tdx-ecdsa

The implementation for tdx-ecdsa is similar to sgx-ecdsa. The difference is that the TDX VM can directly call the DCAP Quote Verification Library without ocall

> Note that tdx-ecdsa attester and verifier are currently only supported in TDX compilation mode. So we will only discuss TDX compilation mode here.

### Implementation in Occlum compilation mode

1. Implementation of tdx-ecdsa `collect_endorsement()`

    Use `tee_qv_get_collateral()` directly.

2. Implementation of tdx-ecdsa `verify_evidence()`

    Use `tdx_qv_verify_quote()` directly.

