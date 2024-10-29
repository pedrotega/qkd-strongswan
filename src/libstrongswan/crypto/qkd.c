/*
 * Copyright (C) 2010-2019 Tobias Brunner
 * Copyright (C) 2005-2010 Martin Willi
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

#include "qkd.h"

typedef struct private_qkd_t private_qkd_t;

ENUM(qkd_method_names, QKD, QKD,
    "QKD",
    );

ENUM(qkd_method_names_short, QKD, QKD,
    "qkd",
    );

struct private_qkd_t{
    qkd_t public;
    chunk_t qkd_id;
    chunk_t qkd_key;
};

METHOD(qkd_t, get_id, chunk_t, 
     private_qkd_t *this)
{
    return this->qkd_id;
}

METHOD(qkd_t, get_key, chunk_t, 
     private_qkd_t *this)
{
    return this->qkd_key;
}

METHOD(qkd_t, set_id, void,
	 private_qkd_t *this, chunk_t id)
{
	this->qkd_id = chunk_clone(id);
}

METHOD(qkd_t, set_key, void,
	 private_qkd_t *this, chunk_t key)
{
	this->qkd_key = chunk_clone(key);
}

void request_qkd_key(private_qkd_t *this)
{
    char *id_q = "bc490419-7d60-487f-adc1-4ddcc177c139";
    char *key_q = "wHHVxRwDJs3/bXd38GHP3oe4svTuRpZS0yCC7x4Ly+s=";

    this->qkd_id = chunk_create(id_q, strlen(id_q));
    this->qkd_key = chunk_create(key_q, strlen(key_q));
}

void request_qkd_key_from_id(private_qkd_t *this, chunk_t id)
{
    char *id_q = "bc490419-7d60-487f-adc1-4ddcc177c139";
    char *key_q = "wHHVxRwDJs3/bXd38GHP3oe4svTuRpZS0yCC7x4Ly+s=";

    if(chunk_compare(id, chunk_create(id_q, strlen(id_q)))) {
        DBG1(DBG_IKE,"\t*** Clave encontrada.");
        this->qkd_id = chunk_create(id_q, strlen(id_q));
        this->qkd_key = chunk_create(key_q, strlen(key_q));
    }
}

private_qkd_t *private_qkd_create()
{
    private_qkd_t *this;

    INIT(this,
        .public = {
            .get_id = _get_id,
            .get_key = _get_key,
            .set_id = _set_id,
            .set_key = _set_key,
        },
    );

    return this;
}

qkd_t *qkd_create()
{
    private_qkd_t *this = private_qkd_create();
    request_qkd_key(this);
    
    return &this->public;
}

qkd_t *qkd_create_from_id(chunk_t id)
{
    private_qkd_t *this = private_qkd_create();
    request_qkd_key_from_id(this, id);
    
    return &this->public;
}

