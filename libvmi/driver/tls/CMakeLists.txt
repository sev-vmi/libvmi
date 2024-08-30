target_sources(vmi_shared PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/tls.c
	${CMAKE_CURRENT_SOURCE_DIR}/tls_events.c
	${CMAKE_CURRENT_SOURCE_DIR}/messages.pb-c.c
	${CMAKE_CURRENT_SOURCE_DIR}/handle_pb_prefix.c
	${CMAKE_CURRENT_SOURCE_DIR}/handle_pb_msg.c)
