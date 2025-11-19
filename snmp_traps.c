// (c) SpecPromDezajn LLC, 2025
// DUNS 362165653
// INN/KPP 6230093924/623001001
// Ryazan, Yablochkova ave., 6, office 718
// Web: https://spd.net.ru
// e-mail: info@spd.net.ru
// Phone: +7 (953) 747-62-55

//v. 30.0

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP

#include <string.h>

#include "lwip/snmp.h"
#include "lwip/sys.h"
#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/prot/iana.h"
#include "snmp_msg.h"
#include "snmp_asn1.h"
#include "snmp_core_priv.h"

#define SNMP_IS_INFORM 1
#define SNMP_IS_TRAP   0

#define SNMP_V3_AUTH_FLAG 0x01
#define SNMP_V3_PRIV_FLAG 0x02

#define SNMP_MSG_MAX_SIZE 2048

#define SNMP_V3_USER_ID 0

extern void snmpv3GetTrapAuth(snmpv3_auth_algo_t *auth, u8_t **auth_key, snmpv3_priv_algo_t *priv, u8_t **priv_key, uint8_t pUserIdx);

struct snmp_msg_trap
{
    const struct snmp_obj_id *enterprise; // source enterprise ID (sysObjectID)
    ip_addr_t sip; // source IP address, raw network order format
    u32_t gen_trap; // generic trap code
    u32_t spc_trap; // specific trap code
    u32_t ts; // timestamp
    u32_t snmp_version; // snmp_version
    u16_t pdulen; // output trap lengths used in ASN encoding encoding pdu length
    u16_t comlen; // encoding community length
    u16_t seqlen; // encoding sequence length
    u16_t vbseqlen; // encoding varbinds sequence length
    s32_t error_status; // error status
    s32_t error_index; // error index
    u8_t trap_or_inform; // trap or inform?
    s32_t request_id; // request ID
    u8_t request_out_type; // request type

#if LWIP_SNMP_V3
    const u8_t *hashedAuthKey;
    const u8_t *hashedPrivKey;
    snmpv3_auth_algo_t auth_algo;
    snmpv3_priv_algo_t priv_algo;

    s32_t msg_id;
    s32_t msg_max_size;
    u8_t msg_flags;
    s32_t msg_security_model;
    u8_t msg_authoritative_engine_id[SNMP_V3_MAX_ENGINE_ID_LENGTH];
    u8_t msg_authoritative_engine_id_len;
    s32_t msg_authoritative_engine_boots;
    s32_t msg_authoritative_engine_time;
    u8_t msg_user_name[SNMP_V3_MAX_USER_LENGTH];
    u8_t msg_user_name_len;
    u8_t msg_authentication_parameters[SNMP_V3_MAX_AUTH_PARAM_LENGTH];
    u8_t msg_authentication_parameters_len;
    u8_t msg_privacy_parameters[SNMP_V3_MAX_PRIV_PARAM_LENGTH];
    u8_t msg_privacy_parameters_len;
    u8_t context_engine_id[SNMP_V3_MAX_ENGINE_ID_LENGTH];
    u8_t context_engine_id_len;
    u8_t context_name[SNMP_V3_MAX_ENGINE_ID_LENGTH];
    u8_t context_name_len;
#endif

    u16_t outbound_pdu_offset;
    u16_t outbound_error_status_offset;
    u16_t outbound_error_index_offset;
    u16_t outbound_varbind_offset;
#if LWIP_SNMP_V3
    u16_t outbound_msg_global_data_offset;
    u16_t outbound_msg_global_data_end;
    u16_t outbound_msg_security_parameters_str_offset;
    u16_t outbound_msg_security_parameters_seq_offset;
    u16_t outbound_msg_security_parameters_end;
    u16_t outbound_msg_authentication_parameters_offset;
    u16_t outbound_scoped_pdu_seq_offset;
    u16_t outbound_scoped_pdu_string_offset;
#endif
};

static u16_t snmp_trap_varbind_sum(struct snmp_msg_trap *trap, struct snmp_varbind *varbinds);
static u16_t snmp_trap_header_sum(struct snmp_msg_trap *trap, u16_t vb_len);
static err_t snmp_trap_header_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
static err_t snmp_trap_varbind_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream, struct snmp_varbind *varbinds);
static u16_t snmp_trap_header_sum_v1_specific(struct snmp_msg_trap *trap);
static u16_t snmp_trap_header_sum_v2c_specific(struct snmp_msg_trap *trap);
static err_t snmp_trap_header_enc_v1_specific(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
static err_t snmp_trap_header_enc_v2c_specific(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
static err_t snmp_prepare_trap_oid(struct snmp_obj_id *dest_snmp_trap_oid, const struct snmp_obj_id *eoid, s32_t generic_trap, s32_t specific_trap);
static void snmp_prepare_necessary_msg_fields(struct snmp_msg_trap *trap_msg, const struct snmp_obj_id *eoid, s32_t generic_trap, s32_t specific_trap, struct snmp_varbind *varbinds);
static err_t snmp_send_msg(struct snmp_msg_trap *trap_msg, struct snmp_varbind *varbinds, u16_t tot_len, ip_addr_t *dip);
static err_t snmp_trap_header_enc_pdu(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);

#if LWIP_SNMP_V3
static void snmp_prepare_v3_trap(struct snmp_msg_trap *trap_msg);
static err_t snmp_send_msg_v3(struct snmp_msg_trap *trap_msg, struct snmp_varbind *varbinds, ip_addr_t *dip);
static err_t snmp_v3_trap_varbind_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream, struct snmp_varbind *varbinds);
static err_t snmp_v3_trap_header_enc_pdu(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
static err_t snmp_trap_header_enc_v3_specific(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
static err_t snmp_v3_trap_header_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
#endif

#define BUILD_EXEC(code) \
 if ((code) != ERR_OK) { \
 LWIP_DEBUGF(SNMP_DEBUG, ("SNMP error during creation of outbound trap frame!")); \
 return ERR_ARG; \
 }

// Agent community string for sending traps
extern const char *snmp_community_trap;

void *snmp_traps_handle;

struct snmp_trap_dst
{
    ip_addr_t dip; // destination IP address in network order
    u8_t enable; // set to 0 when disabled, >0 when enabled
};

static struct snmp_trap_dst trap_dst[SNMP_TRAP_DESTINATIONS];

static u8_t snmp_auth_traps_enabled = 0;

// This is used in functions like snmp_coldstart_trap where user didn't specify which version of trap to use
static u8_t snmp_default_trap_version = SNMP_VERSION_1;

// This is used in trap messages v2c
static s32_t req_id = 1;

// This is used in trap messages v3
static s32_t MsgId = 0;

/**
 * @ingroup snmp_traps
 * Sets enable switch for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param enable switch if 0 destination is disabled >0 enabled.
 *
 * @retval void
 */
void snmp_trap_dst_enable(u8_t dst_idx, u8_t enable)
{
    LWIP_ASSERT_SNMP_LOCKED();

    if (dst_idx < SNMP_TRAP_DESTINATIONS)
        trap_dst[dst_idx].enable = enable;
}

/**
 * @ingroup snmp_traps
 * Sets IPv4 address for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param dst IPv4 address in host order.
 *
 * @retval void
 */
void snmp_trap_dst_ip_set(u8_t dst_idx, const ip_addr_t *dst)
{
    LWIP_ASSERT_SNMP_LOCKED();

    if (dst_idx < SNMP_TRAP_DESTINATIONS)
        ip_addr_set(&trap_dst[dst_idx].dip, dst);
}

/**
 * @ingroup snmp_traps
 * Enable/disable authentication traps
 *
 * @param enable enable SNMP traps
 *
 * @retval void
 */
void snmp_set_auth_traps_enabled(u8_t enable)
{
    snmp_auth_traps_enabled = enable;
}

/**
 * @ingroup snmp_traps
 * Get authentication traps enabled state
 *
 * @return TRUE if traps are enabled, FALSE if they aren't
 */
u8_t snmp_get_auth_traps_enabled(void)
{
    return snmp_auth_traps_enabled;
}

/**
 * @ingroup snmp_traps
 * Choose default SNMP version for sending traps (if not specified, default
version is SNMP_VERSION_1)
 * SNMP_VERSION_1 0
 * SNMP_VERSION_2c 1
 * SNMP_VERSION_3 3
 *
 * @param snmp_version version that will be used for sending traps
 *
 * @retval void
 */
void snmp_set_default_trap_version(u8_t snmp_version)
{
    snmp_default_trap_version = snmp_version;
}

/**
 * @ingroup snmp_traps
 * Get default SNMP version for sending traps
 *
 * @return selected default version:
 * 0 - SNMP_VERSION_1
 * 1 - SNMP_VERSION_2c
 * 3 - SNMP_VERSION_3
 */
u8_t snmp_get_default_trap_version(void)
{
    return snmp_default_trap_version;
}

/**
 * @ingroup snmp_traps
 * Prepares snmpTrapOID for SNMP v2c
 * @param dest_snmp_trap_oid pointer to destination snmpTrapOID
 * @param eoid enterprise oid (can be NULL)
 * @param generic_trap SNMP v1 generic trap
 * @param specific_trap SNMP v1 specific trap
 * @return ERR_OK if completed successfully;
 * ERR_MEM if there wasn't enough memory allocated for destination;
 * ERR_VAL if value for generic trap was incorrect;
 */
static err_t snmp_prepare_trap_oid(struct snmp_obj_id *dest_snmp_trap_oid,
                                   const struct snmp_obj_id *eoid,
                                   s32_t generic_trap,
                                   s32_t specific_trap)
{
    err_t err = ERR_OK;
    const u32_t snmpTrapOID[] = {1, 3, 6, 1, 6, 3, 1, 1, 5}; // please see rfc3584

    if (generic_trap == SNMP_GENTRAP_ENTERPRISE_SPECIFIC)
    {
        if (eoid == NULL)
            MEMCPY(dest_snmp_trap_oid, snmp_get_device_enterprise_oid(), sizeof(*dest_snmp_trap_oid));
        else
            MEMCPY(dest_snmp_trap_oid, eoid, sizeof(*dest_snmp_trap_oid));

        if ((dest_snmp_trap_oid->len + 1) < SNMP_MAX_OBJ_ID_LEN)
            dest_snmp_trap_oid->id[dest_snmp_trap_oid->len++] = specific_trap;
        else
            err = ERR_MEM;
    }
    else
    {
        if ((generic_trap >= SNMP_GENTRAP_COLDSTART) && (generic_trap < SNMP_GENTRAP_ENTERPRISE_SPECIFIC))
        {
            if (sizeof(dest_snmp_trap_oid->id) >= sizeof(snmpTrapOID))
            {
                MEMCPY(&dest_snmp_trap_oid->id, snmpTrapOID, sizeof(snmpTrapOID));

                dest_snmp_trap_oid->len = LWIP_ARRAYSIZE(snmpTrapOID);
                dest_snmp_trap_oid->id[dest_snmp_trap_oid->len++] = generic_trap + 1;
            }
            else
                err = ERR_MEM;
        }
        else
            err = ERR_VAL;
    }

    return err;
}

/**
 * @ingroup snmp_traps
 * Prepare the rest of the necessary fields for trap/notification/inform
message.
 * @param trap_msg message that should be set
 * @param eoid enterprise oid (can be NULL)
 * @param generic_trap SNMP v1 generic trap
 * @param specific_trap SNMP v1 specific trap
 * @param varbinds list of varbinds
 * @retval void
 */
static void snmp_prepare_necessary_msg_fields(struct snmp_msg_trap *trap_msg,
        const struct snmp_obj_id *eoid,
        s32_t generic_trap,
        s32_t specific_trap,
        struct snmp_varbind *varbinds)
{
    if (trap_msg->snmp_version == SNMP_VERSION_1)
    {
        trap_msg->enterprise = (eoid == NULL) ? snmp_get_device_enterprise_oid() : eoid;
        trap_msg->gen_trap = generic_trap;
        trap_msg->spc_trap = (generic_trap == SNMP_GENTRAP_ENTERPRISE_SPECIFIC) ? specific_trap : 0;
        MIB2_COPY_SYSUPTIME_TO(&trap_msg->ts);
    }
    else
        MIB2_COPY_SYSUPTIME_TO((u32_t *)varbinds[0].value); // Copy sysUpTime into the first varbind
}

/**
 * @ingroup snmp_traps
 * Copy trap message structure to pbuf and sends it
 * @param trap_msg contains the data that should be sent
 * @param varbinds list of varbinds
 * @param tot_len total length of encoded data
 * @param dip destination IP address
 * @return ERR_OK if sending was successful
 */
static err_t snmp_send_msg(struct snmp_msg_trap *trap_msg,
                           struct snmp_varbind *varbinds,
                           u16_t tot_len,
                           ip_addr_t *dip)
{
    err_t err = ERR_OK;
    struct pbuf *p = NULL;

    p = pbuf_alloc(PBUF_TRANSPORT, tot_len, PBUF_RAM);

    if (p != NULL)
    {
        struct snmp_pbuf_stream pbuf_stream;
        snmp_pbuf_stream_init(&pbuf_stream, p, 0, tot_len);

        // pass 1, encode packet ino the pbuf(s)
        BUILD_EXEC( snmp_trap_header_enc(trap_msg, &pbuf_stream) );
        BUILD_EXEC( snmp_trap_varbind_enc(trap_msg, &pbuf_stream, varbinds) );

        snmp_stats.outtraps++;
        snmp_stats.outpkts++;

        // send to the TRAP destination
        err = snmp_sendto(snmp_traps_handle, p, dip, LWIP_IANA_PORT_SNMP_TRAP);
        pbuf_free(p);
    }
    else
        err = ERR_MEM;

    return err;
}

/**
 * @ingroup snmp_traps
 * Prepare and sends a generic or enterprise specific trap message,
notification or inform.
 *
 * @param trap_msg defines msg type
 * @param eoid points to enterprise object identifier
 * @param generic_trap is the trap code
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @param varbinds linked list of varbinds to be sent
 * @return ERR_OK when success, ERR_MEM if we're out of memory
 *
 * @note the use of the enterprise identifier field
 * is per RFC1215.
 * Use .iso.org.dod.internet.mgmt.mib-2.snmp for generic traps
 * and .iso.org.dod.internet.private.enterprises.yourenterprise
 * (sysObjectID) for specific traps.
 */
static err_t snmp_send_trap_or_notification_or_inform_generic(struct snmp_msg_trap *trap_msg,
        const struct snmp_obj_id *eoid,
        s32_t generic_trap,
        s32_t specific_trap,
        struct snmp_varbind *varbinds)
{
    struct snmp_trap_dst *td = NULL;
    u16_t i = 0;
    u16_t tot_len = 0;
    err_t err = ERR_OK;
    u32_t timestamp = 0;
    struct snmp_obj_id snmp_trap_oid = { 0 };  // used for converting SNMPv1 generic/specific trap parameter to SNMPv2 snmpTrapOID
    struct snmp_varbind *original_varbinds = varbinds;
    struct snmp_varbind *original_prev = NULL;

    struct snmp_varbind snmp_v2_special_varbinds[] = {
        {
            NULL,
            NULL,
            { 9, {1, 3, 6, 1, 2, 1, 1, 3, 0} }, // oid for sysUpTime.0
            SNMP_ASN1_TYPE_TIMETICKS,
            sizeof(u32_t),
            NULL
        },
        {
            NULL,
            NULL,
            { 11, {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0} }, // oid for snmpTrapOID.0
            SNMP_ASN1_TYPE_OBJECT_ID,
            0,
            NULL
        }
    };

    LWIP_ASSERT_SNMP_LOCKED();

    snmp_v2_special_varbinds[0].next = &snmp_v2_special_varbinds[1];
    snmp_v2_special_varbinds[1].prev = &snmp_v2_special_varbinds[0];

    snmp_v2_special_varbinds[0].value = &timestamp;
    snmp_v2_special_varbinds[1].next = varbinds;

    // see rfc3584
    if (trap_msg->snmp_version >= SNMP_VERSION_2c)
    {
        err = snmp_prepare_trap_oid(&snmp_trap_oid, eoid, generic_trap, specific_trap);

        if (err == ERR_OK)
        {
            snmp_v2_special_varbinds[1].value_len = snmp_trap_oid.len * sizeof(snmp_trap_oid.id[0]);
            snmp_v2_special_varbinds[1].value = snmp_trap_oid.id;

            if (varbinds != NULL)
            {
                original_prev = varbinds->prev;
                varbinds->prev = &snmp_v2_special_varbinds[1];
            }

            varbinds = snmp_v2_special_varbinds;
        }
    }

    for (i = 0, td = &trap_dst[0]; (i < SNMP_TRAP_DESTINATIONS) && (err == ERR_OK); i++, td++)
    {
        if ((td->enable != 0) && !ip_addr_isany(&td->dip))
        {
            // lookup current source address for this dst
            if (snmp_get_local_ip_for_dst(snmp_traps_handle, &td->dip, &trap_msg->sip))
            {
                snmp_prepare_necessary_msg_fields(trap_msg, eoid, generic_trap, specific_trap, varbinds);

                if (trap_msg->snmp_version == SNMP_VERSION_3)
                {
#if LWIP_SNMP_V3
                    // allocate pbuf, fill it and send it
                    err = snmp_send_msg_v3(trap_msg, varbinds, &td->dip);
#else
                    err = ERR_ARG;
#endif
                }
                else
                {
                    // pass 0, calculate length fields
                    tot_len = snmp_trap_varbind_sum(trap_msg, varbinds);
                    tot_len = snmp_trap_header_sum(trap_msg, tot_len);

                    // allocate pbuf, fill it and send it
                    err = snmp_send_msg(trap_msg, varbinds, tot_len, &td->dip);
                }
            }
            else
                err = ERR_RTE;
        }
    }

    if (original_prev != NULL)
        original_varbinds->prev = original_prev;

    req_id++;

    return err;
}

/**
 * @ingroup snmp_traps
 * This function is a wrapper function for preparing and sending generic or
specific traps.
 *
 * @param oid points to enterprise object identifier
 * @param generic_trap is the trap code
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @param varbinds linked list of varbinds to be sent
 * @return ERR_OK when success, ERR_MEM if we're out of memory
 *
 * @note the use of the enterprise identifier field
 * is per RFC1215.
 * Use .iso.org.dod.internet.mgmt.mib-2.snmp for generic traps
 * and .iso.org.dod.internet.private.enterprises.yourenterprise
 * (sysObjectID) for specific traps.
 */

err_t snmp_send_trap(const struct snmp_obj_id* oid,
                     s32_t generic_trap,
                     s32_t specific_trap,
                     struct snmp_varbind *varbinds)
{
    struct snmp_msg_trap trap_msg = {0};

    trap_msg.snmp_version = snmp_default_trap_version;
    trap_msg.trap_or_inform = SNMP_IS_TRAP;

    return snmp_send_trap_or_notification_or_inform_generic(&trap_msg, oid, generic_trap, specific_trap, varbinds);
}

/**
 * @ingroup snmp_traps
 * Send generic SNMP trap
 * @param generic_trap is the trap code
 * return ERR_OK when success
 */
err_t snmp_send_trap_generic(s32_t generic_trap)
{
    err_t err = ERR_OK;
    struct snmp_msg_trap trap_msg = {0};
    trap_msg.snmp_version = snmp_default_trap_version;
    trap_msg.trap_or_inform = SNMP_IS_TRAP;

    if (snmp_default_trap_version == SNMP_VERSION_1)
    {
        static const struct snmp_obj_id oid = { 7, { 1, 3, 6, 1, 2, 1, 11 } };
        err = snmp_send_trap_or_notification_or_inform_generic(&trap_msg, &oid, generic_trap, 0, NULL);
    }
    else
        err = snmp_send_trap_or_notification_or_inform_generic(&trap_msg, NULL, generic_trap, 0, NULL);

    return err;
}

/**
 * @ingroup snmp_traps
 * Send specific SNMP trap with variable bindings
 * @param specific_trap used for enterprise traps (generic_trap = 6)
 * @param varbinds linked list of varbinds to be sent
 * @return ERR_OK when success
 */
err_t snmp_send_trap_specific(s32_t specific_trap, struct snmp_varbind *varbinds)
{
    struct snmp_msg_trap trap_msg = {0};

    trap_msg.snmp_version = snmp_default_trap_version;
    trap_msg.trap_or_inform = SNMP_IS_TRAP;

    return snmp_send_trap_or_notification_or_inform_generic(&trap_msg, NULL, SNMP_GENTRAP_ENTERPRISE_SPECIFIC, specific_trap, varbinds);
}

/**
 * @ingroup snmp_traps
 * Send coldstart trap
 * @retval void
 */
void snmp_coldstart_trap(void)
{
    snmp_send_trap_generic(SNMP_GENTRAP_COLDSTART);
}

/**
 * @ingroup snmp_traps
 * Send authentication failure trap (used internally by agent)
 * @retval void
 */
void snmp_authfail_trap(void)
{
    if (snmp_auth_traps_enabled != 0)
        snmp_send_trap_generic(SNMP_GENTRAP_AUTH_FAILURE);
}

/**
 * @ingroup snmp_traps
 * Sums trap varbinds
 *
 * @param trap Trap message
 * @param varbinds linked list of varbinds
 * @return the required length for encoding of this part of the trap header
 */
static u16_t snmp_trap_varbind_sum(struct snmp_msg_trap *trap, struct snmp_varbind *varbinds)
{
    struct snmp_varbind *varbind;
    u16_t tot_len;
    u8_t tot_len_len;

    tot_len = 0;
    varbind = varbinds;

    while (varbind != NULL)
    {
        struct snmp_varbind_len len;

        if (snmp_varbind_length(varbind, &len) == ERR_OK)
            tot_len += 1 + len.vb_len_len + len.vb_value_len;

        varbind = varbind->next;
    }

    trap->vbseqlen = tot_len;
    snmp_asn1_enc_length_cnt(trap->vbseqlen, &tot_len_len);
    tot_len += 1 + tot_len_len;

    return tot_len;
}

/**
 * @ingroup snmp_traps
 * Sums trap header fields that are specific for SNMP v1
 *
 * @param trap Trap message
 * @return the required length for encoding of this part of the trap header
 */
static u16_t snmp_trap_header_sum_v1_specific(struct snmp_msg_trap *trap)
{
    u16_t tot_len = 0;
    u16_t len = 0;
    u8_t lenlen = 0;

    snmp_asn1_enc_u32t_cnt(trap->ts, &len);
    snmp_asn1_enc_length_cnt(len, &lenlen);
    tot_len += 1 + len + lenlen;

    snmp_asn1_enc_s32t_cnt(trap->spc_trap, &len);
    snmp_asn1_enc_length_cnt(len, &lenlen);
    tot_len += 1 + len + lenlen;

    snmp_asn1_enc_s32t_cnt(trap->gen_trap, &len);
    snmp_asn1_enc_length_cnt(len, &lenlen);
    tot_len += 1 + len + lenlen;

    if (IP_IS_V6_VAL(trap->sip))
    {
#if LWIP_IPV6
        len = sizeof(ip_2_ip6(&trap->sip)->addr);
#endif
    }
    else
    {
#if LWIP_IPV4
        len = sizeof(ip_2_ip4(&trap->sip)->addr);
#endif
    }

    snmp_asn1_enc_length_cnt(len, &lenlen);
    tot_len += 1 + len + lenlen;

    snmp_asn1_enc_oid_cnt(trap->enterprise->id, trap->enterprise->len, &len);
    snmp_asn1_enc_length_cnt(len, &lenlen);
    tot_len += 1 + len + lenlen;

    return tot_len;
}

/**
 * @ingroup snmp_traps
 * Sums trap header fields that are specific for SNMP v2c
 *
 * @param trap Trap message
 * @return the required length for encoding of this part of the trap header
 */
static u16_t snmp_trap_header_sum_v2c_specific(struct snmp_msg_trap *trap)
{
    u16_t tot_len = 0;
    u16_t len = 0;
    u8_t lenlen = 0;

    snmp_asn1_enc_u32t_cnt(req_id, &len);
    snmp_asn1_enc_length_cnt(len, &lenlen);
    tot_len += 1 + len + lenlen;
    snmp_asn1_enc_u32t_cnt(trap->error_status, &len);
    snmp_asn1_enc_length_cnt(len, &lenlen);
    tot_len += 1 + len + lenlen;
    snmp_asn1_enc_u32t_cnt(trap->error_index, &len);
    snmp_asn1_enc_length_cnt(len, &lenlen);
    tot_len += 1 + len + lenlen;

    return tot_len;
}

/**
 * @ingroup snmp_traps
 * Sums trap header field lengths from tail to head and
 * returns trap_header_lengths for second encoding pass.
 *
 * @param trap Trap message
 * @param vb_len varbind-list length
 * @return the required length for encoding the trap header
 */
static u16_t
snmp_trap_header_sum(struct snmp_msg_trap *trap, u16_t vb_len)
{
    u16_t tot_len = vb_len;
    u16_t len = 0;
    u8_t lenlen = 0;

    if (trap->snmp_version == SNMP_VERSION_1) {
        tot_len += snmp_trap_header_sum_v1_specific(trap);
    } else {
        tot_len += snmp_trap_header_sum_v2c_specific(trap);
    }
    trap->pdulen = tot_len;
    snmp_asn1_enc_length_cnt(trap->pdulen, &lenlen);
    tot_len += 1 + lenlen;

    trap->comlen = (u16_t)LWIP_MIN(strlen(snmp_community_trap), 0xFFFF);
    snmp_asn1_enc_length_cnt(trap->comlen, &lenlen);
    tot_len += 1 + lenlen + trap->comlen;

    snmp_asn1_enc_s32t_cnt(trap->snmp_version, &len);
    snmp_asn1_enc_length_cnt(len, &lenlen);
    tot_len += 1 + len + lenlen;

    trap->seqlen = tot_len;
    snmp_asn1_enc_length_cnt(trap->seqlen, &lenlen);
    tot_len += 1 + lenlen;

    return tot_len;
}

/**
 * @ingroup snmp_traps
 * Encodes varbinds.
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @param varbinds linked list of varbinds
 * @retval err_t ERR_OK if successful, ERR_ARG otherwise
 */
static err_t
snmp_trap_varbind_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream
                      *pbuf_stream, struct snmp_varbind *varbinds)
{
    struct snmp_asn1_tlv tlv;
    struct snmp_varbind *varbind;

    varbind = varbinds;

    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->vbseqlen);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

    while (varbind != NULL) {
        BUILD_EXEC( snmp_append_outbound_varbind(pbuf_stream, varbind) );

        varbind = varbind->next;
    }

    return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header PDU part.
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval err_t ERR_OK if successful, ERR_ARG otherwise
 */
static err_t
snmp_trap_header_enc_pdu(struct snmp_msg_trap *trap, struct snmp_pbuf_stream
                         *pbuf_stream)
{
    struct snmp_asn1_tlv tlv;
    /* 'PDU' sequence */
    if (trap->snmp_version == SNMP_VERSION_1) {
        /* TRAP V1 */
        SNMP_ASN1_SET_TLV_PARAMS(tlv, (SNMP_ASN1_CLASS_CONTEXT |
                                       SNMP_ASN1_CONTENTTYPE_CONSTRUCTED | SNMP_ASN1_CONTEXT_PDU_TRAP), 0,
                                 trap->pdulen);
        BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    } else if ((trap->snmp_version == SNMP_VERSION_2c) && (trap->trap_or_inform
               == SNMP_IS_INFORM)) {
        /* TRAP v2 - INFORM */
        SNMP_ASN1_SET_TLV_PARAMS(tlv, (SNMP_ASN1_CLASS_CONTEXT |
                                       SNMP_ASN1_CONTENTTYPE_CONSTRUCTED | SNMP_ASN1_CONTEXT_PDU_INFORM_REQ), 0,
                                 trap->pdulen);
        BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    } else if (trap->snmp_version == SNMP_VERSION_2c) {
        /* TRAP v2 - NOTIFICATION*/
        SNMP_ASN1_SET_TLV_PARAMS(tlv, (SNMP_ASN1_CLASS_CONTEXT |
                                       SNMP_ASN1_CONTENTTYPE_CONSTRUCTED | SNMP_ASN1_CONTEXT_PDU_V2_TRAP), 0,
                                 trap->pdulen);
        BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    }

    return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header part that is SNMP v1 header specific.
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval void
 */
static err_t
snmp_trap_header_enc_v1_specific(struct snmp_msg_trap *trap, struct
                                 snmp_pbuf_stream *pbuf_stream)
{
    struct snmp_asn1_tlv tlv;
    /* object ID */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OBJECT_ID, 0, 0);
    snmp_asn1_enc_oid_cnt(trap->enterprise->id, trap->enterprise->len,
                          &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_oid(pbuf_stream, trap->enterprise->id,
                                  trap->enterprise->len) );

    /* IP addr */
    if (IP_IS_V6_VAL(trap->sip)) {
#if LWIP_IPV6
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_IPADDR, 0,
                                 sizeof(ip_2_ip6(&trap->sip)->addr));
        BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
        BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream, (const u8_t
                                      *)&ip_2_ip6(&trap->sip)->addr, sizeof(ip_2_ip6(&trap->sip)->addr)) );
#endif
    } else {
#if LWIP_IPV4
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_IPADDR, 0,
                                 sizeof(ip_2_ip4(&trap->sip)->addr));
        BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
        BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream, (const u8_t
                                      *)&ip_2_ip4(&trap->sip)->addr, sizeof(ip_2_ip4(&trap->sip)->addr)) );
#endif
    }

    /* generic trap */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(trap->gen_trap, &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->gen_trap) );

    /* specific trap */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(trap->spc_trap, &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->spc_trap) );

    /* timestamp */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_TIMETICKS, 0, 0);
    snmp_asn1_enc_s32t_cnt(trap->ts, &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->ts) );

    return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header part that is SNMP v2c header specific.
 *
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval void
 */
static err_t
snmp_trap_header_enc_v2c_specific(struct snmp_msg_trap *trap, struct
                                  snmp_pbuf_stream *pbuf_stream)
{
    struct snmp_asn1_tlv tlv;
    /* request id */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(req_id, &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, req_id) );

    /* error status */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(trap->error_status, &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len,
                                   trap->error_status) );

    /* error index */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(trap->error_index, &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->error_index)
              );

    return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header from head to tail.
 *
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval void
 */
static err_t
snmp_trap_header_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream
                     *pbuf_stream)
{
    struct snmp_asn1_tlv tlv;

    /* 'Message' sequence */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->seqlen);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

    /* version */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(trap->snmp_version, &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len,
                                   trap->snmp_version) );

    /* community */
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->comlen);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream, (const u8_t
                                  *)snmp_community_trap, trap->comlen) );

    /* PDU */
    BUILD_EXEC( snmp_trap_header_enc_pdu(trap, pbuf_stream) );
    if (trap->snmp_version == SNMP_VERSION_1) {
        /* object ID, IP addr, generic trap, specific trap, timestamp */
        BUILD_EXEC( snmp_trap_header_enc_v1_specific(trap, pbuf_stream) );
    } else if (SNMP_VERSION_2c == trap->snmp_version) {
        /* request id, error status, error index */
        BUILD_EXEC( snmp_trap_header_enc_v2c_specific(trap, pbuf_stream) );
    }

    return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Wrapper function for sending informs
 * @param specific_trap will be appended to enterprise oid [see RFC 3584]
 * @param varbinds linked list of varbinds (at the beginning of this list
function will insert 2 special purpose varbinds [see RFC 3584])
 * @param ptr_request_id [out] variable in which to store request_id needed to
verify acknowledgement
 * @return ERR_OK if successful
 */
err_t
snmp_send_inform_specific(s32_t specific_trap, struct snmp_varbind *varbinds,
                          s32_t *ptr_request_id)
{
    return snmp_send_inform(NULL, SNMP_GENTRAP_ENTERPRISE_SPECIFIC,
                            specific_trap, varbinds, ptr_request_id);
}

/**
 * @ingroup snmp_traps
 * Wrapper function for sending informs
 * @param generic_trap is the trap code
 * @param varbinds linked list of varbinds (at the beginning of this list
function will insert 2 special purpose varbinds [see RFC 3584])
 * @param ptr_request_id [out] variable in which to store request_id needed to
verify acknowledgement
 * @return ERR_OK if successful
 */
err_t
snmp_send_inform_generic(s32_t generic_trap, struct snmp_varbind *varbinds,
                         s32_t *ptr_request_id)
{
    return snmp_send_inform(NULL, generic_trap, 0, varbinds, ptr_request_id);
}

/**
 * @ingroup snmp_traps
 * Generic function for sending informs
 * @param oid points to object identifier
 * @param generic_trap is the trap code
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @param varbinds linked list of varbinds (at the beginning of this list
function will insert 2 special purpose varbinds [see RFC 3584])
 * @param ptr_request_id [out] variable in which to store request_id needed to
verify acknowledgement
 * @return ERR_OK if successful
 */
err_t
snmp_send_inform(const struct snmp_obj_id* oid, s32_t generic_trap, s32_t
                 specific_trap, struct snmp_varbind *varbinds, s32_t *ptr_request_id)
{
    struct snmp_msg_trap trap_msg = {0};
    trap_msg.snmp_version = SNMP_VERSION_2c;
    trap_msg.trap_or_inform = SNMP_IS_INFORM;
    *ptr_request_id = req_id;
    return snmp_send_trap_or_notification_or_inform_generic(&trap_msg, oid,
            generic_trap, specific_trap, varbinds);
}

#if LWIP_SNMP_V3
/**
 * @ingroup snmp_traps
 * Prepare v3 TRAP
 * @param trap_msg message that should be set
 * @retval void
 */
static void snmp_prepare_v3_trap(struct snmp_msg_trap *trap_msg)
{
    const u8_t *id;
    u8_t id_len;
    snmpv3_auth_algo_t auth;
    u8_t *auth_key;
    snmpv3_priv_algo_t priv;
    u8_t *priv_key;

    snmpv3_get_engine_id((const char**)&id, &id_len);

    snmpv3GetTrapAuth(&auth, &auth_key, &priv, &priv_key, SNMP_V3_USER_ID);

    strcpy((char*)trap_msg->context_name, "DefaultContext");
    trap_msg->context_name_len = strlen((char*)trap_msg->context_name);

    trap_msg->msg_authoritative_engine_id_len = id_len;
    memcpy(trap_msg->msg_authoritative_engine_id, id, LWIP_MIN(id_len,
            sizeof(trap_msg->msg_authoritative_engine_id)));
    trap_msg->msg_authoritative_engine_boots = snmpv3_get_engine_boots();
    trap_msg->msg_authoritative_engine_time = snmpv3_get_engine_time();

    snmpv3_get_username((char*)trap_msg->msg_user_name, SNMP_V3_USER_ID);
    trap_msg->msg_user_name_len = strlen((const char*)trap_msg->msg_user_name);

    trap_msg->hashedAuthKey = auth_key;
    trap_msg->hashedPrivKey = priv_key;
    trap_msg->auth_algo = auth;
    trap_msg->priv_algo = priv;

    trap_msg->request_out_type = SNMP_ASN1_CLASS_CONTEXT |
                                 SNMP_ASN1_CONTENTTYPE_CONSTRUCTED | SNMP_ASN1_CONTEXT_PDU_V2_TRAP;

    trap_msg->msg_max_size = SNMP_MSG_MAX_SIZE;

    trap_msg->msg_flags = 0;
    if (id_len)
    {
        if (auth) trap_msg->msg_flags |= SNMP_V3_AUTH_FLAG;
        if (priv) trap_msg->msg_flags |= SNMP_V3_PRIV_FLAG;
    }

    trap_msg->snmp_version = SNMP_VERSION_3;
    trap_msg->msg_security_model = SNMP_VERSION_3;

    trap_msg->msg_id = MsgId++;
    if(MsgId < 0)
        MsgId = 0;
}

/**
 * @ingroup snmp_traps
 * Copy trap message structure to pbuf and sends it
 * @param trap_msg contains the data that should be sent
 * @param varbinds list of varbinds
 * @param dip destination IP address
 * @return ERR_OK if sending was successful
 */
static err_t snmp_send_msg_v3(struct snmp_msg_trap *trap_msg,
                              struct snmp_varbind *varbinds, ip_addr_t *dip)
{
    err_t err = ERR_OK;
    struct pbuf *p = NULL;

    snmp_prepare_v3_trap(trap_msg);

    // allocate pbuf(s)
    p = pbuf_alloc(PBUF_TRANSPORT, 1472, PBUF_RAM);

    if (p != NULL)
    {
        struct snmp_pbuf_stream pbuf_stream;
        snmp_pbuf_stream_init(&pbuf_stream, p, 0, p->tot_len);

        // encode packet ino the pbuf(s)
        BUILD_EXEC(snmp_v3_trap_header_enc(trap_msg, &pbuf_stream));
        BUILD_EXEC(snmp_v3_trap_varbind_enc(trap_msg, &pbuf_stream, varbinds));

        struct snmp_asn1_tlv tlv;
        u16_t frame_size;

        frame_size = pbuf_stream.offset;
        u8_t outbound_padding = 0;

#if LWIP_SNMP_V3_CRYPTO
        // Calculate padding for encryption
        if ((trap_msg->msg_flags & SNMP_V3_PRIV_FLAG))
        {
            outbound_padding = (8 - (u8_t)((frame_size - trap_msg->outbound_scoped_pdu_seq_offset) & 0x07)) & 0x07;

            for (u8_t i = 0; i < outbound_padding; i++)
                BUILD_EXEC( snmp_pbuf_stream_write(&pbuf_stream, 0) );
        }
#endif

        // complete missing length in 'Message' sequence ; 'Message' tlv is located at the beginning (offset 0)
        // - type - length_len(fixed, see snmp_prepare_outbound_frame())
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, frame_size + outbound_padding - 1 - 3);

        BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, 0));
        BUILD_EXEC( snmp_ans1_enc_tlv(&pbuf_stream, &tlv) );

        // complete missing length in 'globalData' sequence
        // - type - length_len(fixed, see snmp_prepare_outbound_frame())
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 1, trap_msg->outbound_msg_global_data_end - trap_msg->outbound_msg_global_data_offset - 1 - 1);
        BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_msg_global_data_offset));
        BUILD_EXEC(snmp_ans1_enc_tlv(&pbuf_stream, &tlv));

        // complete missing length in 'msgSecurityParameters' sequence
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 1, trap_msg->outbound_msg_security_parameters_end - trap_msg->outbound_msg_security_parameters_str_offset - 1 - 1);
        BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_msg_security_parameters_str_offset));
        BUILD_EXEC(snmp_ans1_enc_tlv(&pbuf_stream, &tlv));

        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 1, trap_msg->outbound_msg_security_parameters_end - trap_msg->outbound_msg_security_parameters_seq_offset - 1 - 1);
        BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_msg_security_parameters_seq_offset));
        BUILD_EXEC(snmp_ans1_enc_tlv(&pbuf_stream, &tlv));

        // complete missing length in scoped PDU sequence
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, frame_size - trap_msg->outbound_scoped_pdu_seq_offset - 1 - 3);
        BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_scoped_pdu_seq_offset));
        BUILD_EXEC(snmp_ans1_enc_tlv(&pbuf_stream, &tlv));

        // complete missing length in 'PDU' sequence
        // - type - length_len(fixed, see snmp_prepare_outbound_frame())
        SNMP_ASN1_SET_TLV_PARAMS(tlv, trap_msg->request_out_type, 3, frame_size - trap_msg->outbound_pdu_offset - 1 - 3);
        BUILD_EXEC( snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_pdu_offset));
        BUILD_EXEC( snmp_ans1_enc_tlv(&pbuf_stream, &tlv));

        // process and encode final error status
        if (trap_msg->error_status != 0)
        {
            u16_t len;
            snmp_asn1_enc_s32t_cnt(trap_msg->error_status, &len);

            if (len != 1)
                // error, we only reserved one byte for it
                return ERR_ARG;

            BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_error_status_offset));
            BUILD_EXEC(snmp_asn1_enc_s32t(&pbuf_stream, len, trap_msg->error_status));

            if (trap_msg->error_status == SNMP_ERR_TOOBIG)
                trap_msg->error_index = 0; // defined by RFC 1157
            else
            {
                if (trap_msg->error_index == 0)
                {
                    //TODO:
                    // set index to varbind where error occurred (if not already set before, e.g. during GetBulk processing)
// FIXME?!?
//trap_msg->error_index = trap_msg->inbound_varbind_enumerator.varbind_count;
                }
            }
        }

        // encode final error index
        if (trap_msg->error_index != 0)
        {
            u16_t len;
            snmp_asn1_enc_s32t_cnt(trap_msg->error_index, &len);

            if (len != 1)
                // error, we only reserved one byte for it
                return ERR_VAL;

            BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_error_index_offset));
            BUILD_EXEC(snmp_asn1_enc_s32t(&pbuf_stream, len, trap_msg->error_index));
        }

        // complete missing length in 'VarBindList' sequence ; 'VarBindList' tlv is located directly before varbind offset
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, frame_size - trap_msg->outbound_varbind_offset);
        // - type - length_len(fixed, see snmp_prepare_outbound_frame())
        BUILD_EXEC( snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_varbind_offset - 1 - 3) );
        BUILD_EXEC( snmp_ans1_enc_tlv(&pbuf_stream, &tlv) );

        // Authenticate response
#if LWIP_SNMP_V3_CRYPTO
        // Encrypt response
        if ((trap_msg->msg_flags & SNMP_V3_PRIV_FLAG))
        {
            // complete missing length in PDU sequence
            BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_scoped_pdu_string_offset));
            SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 3, frame_size + outbound_padding - trap_msg->outbound_scoped_pdu_string_offset - 1 - 3);

            BUILD_EXEC(snmp_ans1_enc_tlv(&pbuf_stream, &tlv));
            BUILD_EXEC(snmpv3_crypt(&pbuf_stream, tlv.value_len,
                                    trap_msg->hashedPrivKey,
                                    trap_msg->msg_privacy_parameters,
                                    trap_msg->msg_authoritative_engine_boots,
                                    trap_msg->msg_authoritative_engine_time,
                                    trap_msg->priv_algo, SNMP_V3_PRIV_MODE_ENCRYPT));
        }

        if ((trap_msg->msg_flags & SNMP_V3_AUTH_FLAG))
        {
            u8_t hmac[20];

            BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, 0));
            BUILD_EXEC(snmpv3_auth(&pbuf_stream, frame_size + outbound_padding, trap_msg->hashedAuthKey, trap_msg->auth_algo, hmac));

            MEMCPY(trap_msg->msg_authentication_parameters, hmac, SNMP_V3_MAX_AUTH_PARAM_LENGTH);
            BUILD_EXEC(snmp_pbuf_stream_seek_abs(&pbuf_stream, trap_msg->outbound_msg_authentication_parameters_offset));

            SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 1, SNMP_V3_MAX_AUTH_PARAM_LENGTH);
            BUILD_EXEC(snmp_ans1_enc_tlv(&pbuf_stream, &tlv));
            BUILD_EXEC(snmp_asn1_enc_raw(&pbuf_stream, trap_msg->msg_authentication_parameters, SNMP_V3_MAX_AUTH_PARAM_LENGTH));
        }
#endif

        pbuf_realloc(p, frame_size + outbound_padding);

        snmp_stats.outtraps++;
        snmp_stats.outpkts++;

        // send to the TRAP destination
        err = snmp_sendto(snmp_traps_handle, p, dip, LWIP_IANA_PORT_SNMP_TRAP);
        pbuf_free(p);
    }
    else
        err = ERR_MEM;

    return err;
}

/**
 * @ingroup snmp_traps
 * Encodes varbinds.
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @param varbinds linked list of varbinds
 * @retval err_t ERR_OK if successful, ERR_ARG otherwise
 */
static err_t snmp_v3_trap_varbind_enc(struct snmp_msg_trap *trap,
                                      struct snmp_pbuf_stream *pbuf_stream,
                                      struct snmp_varbind *varbinds)
{
    struct snmp_asn1_tlv tlv;
    struct snmp_varbind *varbind;

    varbind = varbinds;

    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, 0);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

    trap->outbound_varbind_offset = pbuf_stream->offset;

    while (varbind != NULL)
    {
        BUILD_EXEC( snmp_append_outbound_varbind(pbuf_stream, varbind));
        varbind = varbind->next;
    }

    return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header PDU part.
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval err_t ERR_OK if successful, ERR_ARG otherwise
 */
static err_t snmp_v3_trap_header_enc_pdu(struct snmp_msg_trap *trap,
        struct snmp_pbuf_stream *pbuf_stream)
{
    struct snmp_asn1_tlv tlv;

    // 'PDU' sequence
    if (trap->trap_or_inform == SNMP_IS_TRAP)
    {
        // TRAP v2 - NOTIFICATION
        SNMP_ASN1_SET_TLV_PARAMS(tlv, trap->request_out_type, 3, 0);
        BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    }
    else
        return ERR_ARG;

    return ERR_OK;
}

/*
 * @ingroup snmp_traps
 * Encodes trap header part that is SNMP v3 header specific.
 *
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval void
 */
static err_t snmp_trap_header_enc_v3_specific(struct snmp_msg_trap *trap,
        struct snmp_pbuf_stream *pbuf_stream)
{
    struct snmp_asn1_tlv tlv;

    // request id
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(req_id, &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, req_id) );

    // error status
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    trap->outbound_error_status_offset = pbuf_stream->offset;
    BUILD_EXEC( snmp_pbuf_stream_write(pbuf_stream, 0) );

    // error index
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    trap->outbound_error_index_offset = pbuf_stream->offset;
    BUILD_EXEC( snmp_pbuf_stream_write(pbuf_stream, 0) );

    return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header from head to tail.
 *
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval void
 */
static err_t snmp_v3_trap_header_enc(struct snmp_msg_trap *trap,
                                     struct snmp_pbuf_stream *pbuf_stream)
{
    struct snmp_asn1_tlv tlv;

    // 'Message' sequence
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, 0);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

    // version
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(trap->snmp_version, &tlv.value_len);
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->snmp_version) );

    const char *id;

    // globalData
    trap->outbound_msg_global_data_offset = pbuf_stream->offset;
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 1, 0);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));

    // msgID
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
    snmp_asn1_enc_s32t_cnt(trap->msg_id, &tlv.value_len);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->msg_id));

    // msgMaxSize
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
    snmp_asn1_enc_s32t_cnt(trap->msg_max_size, &tlv.value_len);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->msg_max_size));

    // msgFlags
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 1);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, &trap->msg_flags, 1));

    // msgSecurityModel
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
    snmp_asn1_enc_s32t_cnt(trap->msg_security_model, &tlv.value_len);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->msg_security_model));

    // end of msgGlobalData
    trap->outbound_msg_global_data_end = pbuf_stream->offset;

    // msgSecurityParameters
    trap->outbound_msg_security_parameters_str_offset = pbuf_stream->offset;
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 1, 0);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));

    trap->outbound_msg_security_parameters_seq_offset = pbuf_stream->offset;
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 1, 0);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));

    // msgAuthoritativeEngineID
    snmpv3_get_engine_id(&id, &trap->msg_authoritative_engine_id_len);
    MEMCPY(trap->msg_authoritative_engine_id, id, trap->msg_authoritative_engine_id_len);
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->msg_authoritative_engine_id_len);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, trap->msg_authoritative_engine_id, trap->msg_authoritative_engine_id_len));

    trap->msg_authoritative_engine_time = snmpv3_get_engine_time();
    trap->msg_authoritative_engine_boots = snmpv3_get_engine_boots();

    // msgAuthoritativeEngineBoots
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(trap->msg_authoritative_engine_boots, &tlv.value_len);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->msg_authoritative_engine_boots));

    // msgAuthoritativeEngineTime
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(trap->msg_authoritative_engine_time, &tlv.value_len);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->msg_authoritative_engine_time));

    // msgUserName
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->msg_user_name_len);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, trap->msg_user_name, trap->msg_user_name_len));

#if LWIP_SNMP_V3_CRYPTO
    // msgAuthenticationParameters
    if (trap->msg_flags & SNMP_V3_AUTH_FLAG)
    {
        memset(trap->msg_authentication_parameters, 0, SNMP_V3_MAX_AUTH_PARAM_LENGTH);
        trap->outbound_msg_authentication_parameters_offset = pbuf_stream->offset;
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 1, SNMP_V3_MAX_AUTH_PARAM_LENGTH);
        BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
        BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, trap->msg_authentication_parameters, SNMP_V3_MAX_AUTH_PARAM_LENGTH));
    }
    else
#endif
    {
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 0);
        BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    }

#if LWIP_SNMP_V3_CRYPTO
    // msgPrivacyParameters
    if (trap->msg_flags & SNMP_V3_PRIV_FLAG)
    {
        snmpv3_build_priv_param(trap->msg_privacy_parameters);

        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, SNMP_V3_MAX_PRIV_PARAM_LENGTH);
        BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
        BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, trap->msg_privacy_parameters, SNMP_V3_MAX_PRIV_PARAM_LENGTH));
    }
    else
#endif
    {
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 0);
        BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    }

    // End of msgSecurityParameters, so we can calculate the length of this sequence later
    trap->outbound_msg_security_parameters_end = pbuf_stream->offset;

#if LWIP_SNMP_V3_CRYPTO
    // For encryption we have to encapsulate the payload in an octet string
    if (trap->msg_flags & SNMP_V3_PRIV_FLAG)
    {
        trap->outbound_scoped_pdu_string_offset = pbuf_stream->offset;
        SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 3, 0);
        BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    }
#endif
    // Scoped PDU Encryption context
    trap->outbound_scoped_pdu_seq_offset = pbuf_stream->offset;
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, 0);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));

    // contextEngineID
    snmpv3_get_engine_id(&id, &trap->context_engine_id_len);
    MEMCPY(trap->context_engine_id, id, trap->context_engine_id_len);
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->context_engine_id_len);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, trap->context_engine_id, trap->context_engine_id_len));

    // contextName
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->context_name_len);
    BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
    BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, trap->context_name, trap->context_name_len));

    // PDU
    trap->outbound_pdu_offset = pbuf_stream->offset;
    BUILD_EXEC( snmp_v3_trap_header_enc_pdu(trap, pbuf_stream));
    // request id, error status, error index
    BUILD_EXEC( snmp_trap_header_enc_v3_specific(trap, pbuf_stream));

    return ERR_OK;
}
#endif

#endif
