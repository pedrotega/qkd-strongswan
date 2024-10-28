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
typedef struct diffie_hellman_params_t diffie_hellman_params_t;

#include <library.h>

/**
 * Quantum key distribution.
 */
enum qkd_method_t {
	QKD = 1,
};

/**
 * enum name for qkd_method_t.
 */
extern char *qkd_method_names;

/**
 * enum names for qkd_method_t (matching proposal keywords).
 */
extern char *qkd_method_names_short;

/**
 * Implementation of a key exchange algorithms (e.g. Diffie-Hellman).
 */
struct qkd_t {
    bool (*get_qkd_key)(qkd_t *this, chunk_t *qkd_id);

    bool (*set_qkd_key)(qkd_t *this, chunk_t value);

    bool (*get_qkd_id)(qkd_t *this, chunk_t *qkd_id);

    bool (*set_qkd_id)(qkd_t *this, chunk_t value);
};

qkd_t qkd_create();

#endif /** QKD_H_ @}*/
