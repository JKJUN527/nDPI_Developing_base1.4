#include "ndpi_utils.h"
#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_RIP
void ndpi_search_rip(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t payload_command ;
  u_int16_t payload_afi ;//address Family identifier
  u_int32_t payload_metric ;

  if (packet->payload_packet_len < 24)//minsize 24 B
	return;
  if (packet->payload_packet_len >512){
    NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "exclude rip cause len larger 512.\n");
    goto EXIT;
  }
  payload_command = packet->payload[0] & 0xff;
  payload_metric = ntohl(get_u_int32_t(packet->payload,4*5));
  payload_afi = ntohs(get_u_int16_t(packet->payload,4));
  /* Check whether this is an rip flow */
  switch(packet->payload[1] & 0xFF){
       case 0x01://rip v1
            if(packet->payload_packet_len >=24
            &&get_u_int16_t(packet->payload,2)==htons(0x0000)
            &&get_u_int16_t(packet->payload,6)==htons(0x0000)
            &&(payload_command <= 6 && payload_command >=1)
            ){
                goto FOUND;
            }else{
                NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "exclude rip over ripV1.\n");
                goto EXIT;
            }
            break;
       case 0x02://rip v2
            NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "payload_afi is %x .\n",payload_afi);
            if(payload_afi == 0xffff){//v2 authentication
                payload_metric = ntohl(get_u_int32_t(packet->payload,4*5+20));
                NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "payload_metric is %u.\n",payload_metric);
            }
            if(packet->payload_packet_len >=24
            &&get_u_int16_t(packet->payload,2)==htons(0x0000)
            &&(payload_metric >=1 && payload_metric <=16)
            &&(payload_command ==1 ||payload_command ==2)
            ){
                goto FOUND;
            }else{
                NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "exclude rip metric is %u.\n",payload_metric);
                NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "exclude rip over ripV2.\n");
                goto EXIT;
            }
        default:
            NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "exclude rip cause version number.\n");
            goto EXIT;
  
  }
FOUND:
    NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "Found rip.\n");
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RIP, NDPI_REAL_PROTOCOL);	
    return;
EXIT:
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RIP);
    return;
 /*
  if(
  	(packet->payload_packet_len <= 512)
     && (((packet->payload[1] & 0xFF) == 0x01) || ((packet->payload[1] & 0xFF) == 0x02))
     && (get_u_int16_t(packet->payload, 2)==htons(0x0000))
     && (get_u_int16_t(packet->payload, 6)==htons(0x0000))
     && (( (payload_command =< 6)&&(payload_command >=1))
     ) ){
    NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "Found rip.\n");
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RIP, NDPI_REAL_PROTOCOL);	
  } else {
    NDPI_LOG(NDPI_PROTOCOL_RIP, ndpi_struct, NDPI_LOG_DEBUG, "exclude rip.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RIP);
  }
  */
}

#endif


