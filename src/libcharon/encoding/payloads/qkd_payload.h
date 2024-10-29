/*
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup qkd_payload qkd_payload
 * @{ @ingroup payloads
 */

#ifndef QKD_PAYLOAD_H_
#define QKD_PAYLOAD_H_

typedef struct qkd_payload_t qkd_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>

/**
 * Class representing an IKEv1/IKEv2 VENDOR ID payload.
 *
 * The VENDOR ID payload format is described in RFC section 3.12.
 */
struct qkd_payload_t {

	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Set the data value.
	 *
	 * @param data			chunk containing the data of the QKD ID
	 */
	void (*set_data) (qkd_payload_t *this, chunk_t data);

	/**
	 * Get data.
	 *
	 * @return		a chunk containing the cloned QKD ID
	 */
	chunk_t (*get_data)(qkd_payload_t *this);

	/**
	 * Destroy qkd_payload_t object.
	 */
	void (*destroy)(qkd_payload_t *this);
};

/**
 * Creates an empty QKD payload for IKEv1 or IKEv2.
 *
 * @@param type		PLV2_QKD or PLV1_QKD
 * @return			QKD ID payload
 */
qkd_payload_t *qkd_payload_create(payload_type_t type);

#endif /** QKD_PAYLOAD_H_ @}*/
