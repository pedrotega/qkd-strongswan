/*
 * Copyright (C) 2010-2019 Tobias Brunner
 * Copyright (C) 2005-2007 Martin Willi
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
 * @defgroup qkd qkd
 * @{ @ingroup crypto
 */

#ifndef QKD_H_
#define QKD_H_

typedef enum qkd_method_t qkd_method_t;
typedef struct qkd_t qkd_t;

#include <library.h>

/**
 * Quantum Key Distribution.
 */

enum qkd_method_t {
	QKD = 1
};

/**
 * enum name for qkd_method_t.
 */
extern enum_name_t *qkd_method_names;

/**
 * enum names for qkd_method_t (matching proposal keywords).
 */
extern enum_name_t *qkd_method_names_short;

struct qkd_t {
	/**
	 * Get id.
	 *
	 * @return		a chunk containing the ID of the QKD key.
	 */
	chunk_t (*get_id)(qkd_t *this);

  /**
	 * Get key.
	 *
	 * @return		a chunk containing the QKD key.
	 */
	chunk_t (*get_key)(qkd_t *this);

  /**
	 * Set the QKD ID value.
	 *
	 * @param id			chunk containing the data of the QKD ID
	 */
	void (*set_id) (qkd_t *this, chunk_t id);

  /**
	 * Set the QKD KEY value.
	 *
	 * @param key			chunk containing the data of the QKD Key
	 */
	void (*set_key) (qkd_t *this, chunk_t key);
};

/**
 * Do a request a key to our KMS and return and object QKD.
 * 
 * @return			QKD object.
 */
qkd_t *qkd_create();

/**
 * Do a request a key to our KMS from an ID and return and object QKD.
 * 
 * @param id			chunk containing the data of the QKD ID
 * 
 * @return			QKD object.
 */
qkd_t *qkd_create_from_id(chunk_t id);


#endif /** QKD_H_ @}*/