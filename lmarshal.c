/*
* lmarshal.c
* A Lua library for serializing and deserializing Lua values
* Richard Hundt <richardhundt@gmail.com>
*
* License: MIT
*
* Copyright (c) 2014 Victor Liu - modified for Lua 5.2
* Copyright (c) 2010 Richard Hundt
*
* Permission is hereby granted, free of charge, to any person
* obtaining a copy of this software and associated documentation
* files (the "Software"), to deal in the Software without
* restriction, including without limitation the rights to use,
* copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following
* conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
* OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
* OTHER DEALINGS IN THE SOFTWARE.
*/

/* Changes
 *   2014-05-25 vkl Removed __persist support and upvalue support since
 *                  I can't get it to work in Lua 5.2. Standardized the
 *                  length datatype in serialized stream.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "lmarshal.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#define MAR_TREF 1
#define MAR_TVAL 2
#define MAR_TUSR 3

#define MAR_MAGIC ((char)0x8e)

typedef uint32_t mar_size_type;


static int mar_encode_table(lua_State *L, int ind_cycletab, mar_buffer *buf, size_t *idx);
static int mar_decode_table(lua_State *L, int ind_cycletab, const char* buf, size_t len, size_t *idx);

void mar_buffer_init(lua_State *L, mar_buffer *buf){
	buf->size = 128;
	buf->seek = 0;
	buf->head = 0;
	if(!(buf->data = malloc(buf->size))) luaL_error(L, "Out of memory!");
}

void mar_buffer_free(lua_State* L, mar_buffer *buf){
	free(buf->data);
}

int mar_buffer_write(lua_State* L, const char* str, size_t len, mar_buffer *buf){
	if (len > UINT32_MAX) luaL_error(L, "buffer too long");
	if (buf->size - buf->head < len){
		size_t new_size = buf->size << 1;
		size_t cur_head = buf->head;
		while (new_size - cur_head <= len){
			new_size = new_size << 1;
		}
		if (!(buf->data = realloc(buf->data, new_size))){
			luaL_error(L, "Out of memory!");
		}
		buf->size = new_size;
	}
	memcpy(&buf->data[buf->head], str, len);
	buf->head += len;
	return 0;
}
static int buf_write_byte(lua_State* L, char byte, mar_buffer *buf){
	return mar_buffer_write(L, &byte, 1, buf);
}
static int buf_write_len(lua_State* L, size_t len, mar_buffer *buf){
	mar_size_type l = len;
	return mar_buffer_write(L, (char*)&l, sizeof(mar_size_type), buf);
}

const char* mar_buffer_read(lua_State *L, mar_buffer *buf, size_t *len){
	if (buf->seek < buf->head){
		buf->seek = buf->head;
		*len = buf->seek;
		return buf->data;
	}
	*len = 0;
	return NULL;
}
char buf_read_byte(lua_State *L, const char **buf, size_t *len){
	char ret = (*buf)[0];
	if(NULL != len){ (*len)--; }
	(*buf)++;
	return ret;
}
size_t buf_read_len(lua_State *L, const char **buf, size_t *len){
	mar_size_type *ptr = (mar_size_type*)*buf;
	size_t ret = ptr[0];
	if(NULL != len){ (*len) -= sizeof(mar_size_type); }
	*buf = (const char*)(ptr+1);
	return ret;
}
/*
void print_item(lua_State *L, int ind){
	printf("type: %s, ", lua_typename(L, lua_type(L, ind)));
	int type = lua_type(L, ind);
	switch(type){
	case LUA_TNUMBER:
		printf("  number val = %g", lua_tonumber(L, ind));
		break;
	case LUA_TBOOLEAN:
		printf("  bool val = %d", lua_toboolean(L, ind));
		break;
	case LUA_TSTRING:
		printf("  str val = %s", lua_tostring(L, ind));
		break;
	case LUA_TFUNCTION:
		{
			lua_Debug dbg;
			lua_pushvalue(L, ind);
			lua_getinfo(L, ">nuS", &dbg);
			printf("  func name = %s", dbg.name);
		}
		break;
	case LUA_TTABLE:
		printf("  table len = %d", (int)lua_rawlen(L, ind));
		break;
	default:
		break;
	}
}*/

static void mar_encode_value(lua_State *L, int ind_cycletab, mar_buffer *buf, int val, size_t *idx)
{
//printf("top0 = %d\n", lua_gettop(L));
	size_t l;
	int val_type = lua_type(L, val);
	lua_pushvalue(L, val);
//printf("top1 = %d\n", lua_gettop(L));
	buf_write_byte(L, val_type, buf);
	switch (val_type){
	case LUA_TBOOLEAN: {
		char val = lua_toboolean(L, -1);
		buf_write_byte(L, val, buf);
		break;
	}
	case LUA_TSTRING: {
		const char *str_val = lua_tolstring(L, -1, &l);
		buf_write_len(L, l, buf);
		mar_buffer_write(L, str_val, l, buf);
		break;
	}
	case LUA_TNUMBER: {
		lua_Number num_val = lua_tonumber(L, -1);
		mar_buffer_write(L, (void*)&num_val, sizeof(lua_Number), buf);
		break;
	}
	case LUA_TTABLE: {
		int ref;
		lua_pushvalue(L, -1);
		lua_rawget(L, ind_cycletab);
		if (!lua_isnil(L, -1)){
			ref = lua_tointeger(L, -1);
			buf_write_byte(L, MAR_TREF, buf);
			buf_write_len(L, ref, buf);
			lua_pop(L, 1);
		}else{
			mar_buffer rec_buf;
			lua_pop(L, 1); /* pop nil */

			lua_pushvalue(L, -1);
			lua_pushinteger(L, (*idx)++);
			lua_rawset(L, ind_cycletab);

			lua_pushvalue(L, -1);
			mar_buffer_init(L, &rec_buf);
			mar_encode_table(L, ind_cycletab, &rec_buf, idx);
			lua_pop(L, 1);

			buf_write_byte(L, MAR_TVAL, buf);
			buf_write_len(L, rec_buf.head, buf);
			mar_buffer_write(L, rec_buf.data,rec_buf.head, buf);
			mar_buffer_free(L, &rec_buf);
		}
		break;
	}
	case LUA_TFUNCTION: {
		int ref;
		lua_pushvalue(L, -1);
		lua_rawget(L, ind_cycletab);
		if (!lua_isnil(L, -1)){
			ref = lua_tointeger(L, -1);
			buf_write_byte(L, MAR_TREF, buf);
			buf_write_len(L, ref, buf);
			lua_pop(L, 1);
		}else{
			mar_buffer rec_buf;
			lua_Debug ar;
			lua_pop(L, 1); /* pop nil */

			lua_pushvalue(L, -1); //printf("type = %s\n", lua_typename(L, lua_type(L, -1)));
			lua_getinfo(L, ">nuS", &ar); //printf("what = %s, name = %s\n", ar.what, ar.name);
			if(ar.what[0] != 'L'){
				//luaL_error(L, "attempt to persist a C function '%s'", ar.name);
				break;
			}
			lua_pushvalue(L, -1);
			lua_pushinteger(L, (*idx)++);
			lua_rawset(L, ind_cycletab);

			lua_pushvalue(L, -1);
			mar_buffer_init(L, &rec_buf);
			lua_dump(L, (lua_Writer)mar_buffer_write, &rec_buf);

			buf_write_byte(L, MAR_TVAL, buf);
			buf_write_len(L, rec_buf.head, buf);
			mar_buffer_write(L, rec_buf.data, rec_buf.head, buf);
			mar_buffer_free(L, &rec_buf);
			lua_pop(L, 1);
		}

		break;
	}
	case LUA_TUSERDATA: {
//printf("topA = %d\n", lua_gettop(L));
		int ref;
		lua_pushvalue(L, -1);
		lua_rawget(L, ind_cycletab);
		if(!lua_isnil(L, -1)){
			ref = lua_tointeger(L, -1);
			buf_write_byte(L, MAR_TREF, buf);
			buf_write_len(L, ref, buf);
			lua_pop(L, 1);
		}else{
			lua_pop(L, 1); /* pop nil */
		}
//printf("topB = %d\n", lua_gettop(L));
		break;
	}
	case LUA_TNIL: break;
	default:
		luaL_error(L, "invalid value type (%s)", lua_typename(L, val_type));
	}
//printf("topN-1 = %d\n", lua_gettop(L));
	lua_pop(L, 1);
//printf("topN = %d\n", lua_gettop(L));
}

static int mar_encode_table(lua_State *L, int ind_cycletab, mar_buffer *buf, size_t *idx){
	lua_pushnil(L);
	while(lua_next(L, -2) != 0){
//printf("key "); print_item(L, -2); printf("\n");
		mar_encode_value(L, ind_cycletab, buf, -2, idx);
//printf("val "); print_item(L, -1); printf("\n");
		mar_encode_value(L, ind_cycletab, buf, -1, idx);
		lua_pop(L, 1);
	}
	return 1;
}

#define mar_incr_ptr(l) \
	if (((*p)-buf)+(l) > len) luaL_error(L, "bad code"); (*p) += (l);

#define mar_next_len(l) \
	if (((*p)-buf)+sizeof(mar_size_type) > len) luaL_error(L, "bad code"); \
	l = *(mar_size_type*)*p; (*p) += sizeof(mar_size_type);

static void mar_decode_value(lua_State *L, int ind_cycletab, const char *buf, size_t len, const char **p, size_t *idx){
	size_t l;
	char val_type = buf_read_byte(L, p, NULL);
	switch (val_type){
	case LUA_TBOOLEAN:
		lua_pushboolean(L, buf_read_byte(L, p, NULL));
		break;
	case LUA_TNUMBER:
		lua_pushnumber(L, *(lua_Number*)*p);
		mar_incr_ptr(sizeof(lua_Number));
		break;
	case LUA_TSTRING:
		l = buf_read_len(L, p, NULL);
		lua_pushlstring(L, *p, l);
		mar_incr_ptr(l);
		break;
	case LUA_TTABLE: {
		char tag = buf_read_byte(L, p, NULL);
		if(tag == MAR_TREF){
			int ref = buf_read_len(L, p, NULL);
			lua_rawgeti(L, ind_cycletab, ref);
		}else if (tag == MAR_TVAL){
			l = buf_read_len(L, p, NULL);
			lua_newtable(L);
			lua_pushvalue(L, -1);
			lua_rawseti(L, ind_cycletab, (*idx)++);
			mar_decode_table(L, ind_cycletab, *p, l, idx);
			mar_incr_ptr(l);
		}else if (tag == MAR_TUSR){
			l = buf_read_len(L, p, NULL);
			lua_newtable(L);
			mar_decode_table(L, ind_cycletab, *p, l, idx);
			lua_rawgeti(L, -1, 1);
			lua_call(L, 0, 1);
			lua_remove(L, -2);
			lua_pushvalue(L, -1);
			lua_rawseti(L, ind_cycletab, (*idx)++);
			mar_incr_ptr(l);
		}else{
			luaL_error(L, "bad encoded data");
		}
		break;
	}
	case LUA_TFUNCTION: {
		mar_buffer dec_buf;
		char tag = *(char*)*p;
		mar_incr_ptr(1);
		if (tag == MAR_TREF){
			int ref = buf_read_len(L, p, NULL);
			lua_rawgeti(L, ind_cycletab, ref);
		}else{
			l = buf_read_len(L, p, NULL);
			dec_buf.data = (char*)*p;
			dec_buf.size = l;
			dec_buf.head = l;
			dec_buf.seek = 0;
			lua_load(L, (lua_Reader)mar_buffer_read, &dec_buf, "=marshal", NULL);
			mar_incr_ptr(l);

			lua_pushvalue(L, -1);
			lua_rawseti(L, ind_cycletab, (*idx)++);
		}
		break;
	}
	case LUA_TUSERDATA: {
		char tag = buf_read_byte(L, p, NULL);
		if (tag == MAR_TREF){
			int ref = buf_read_len(L, p, NULL);
			lua_rawgeti(L, ind_cycletab, ref);
		}else if (tag == MAR_TUSR){
			l = buf_read_len(L, p, NULL);
			lua_newtable(L);
			mar_decode_table(L, ind_cycletab, *p, l, idx);
			lua_rawgeti(L, -1, 1);
			lua_call(L, 0, 1);
			lua_remove(L, -2);
			lua_pushvalue(L, -1);
			lua_rawseti(L, ind_cycletab, (*idx)++);
			mar_incr_ptr(l);
		}else{ /* tag == MAR_TVAL */
			lua_pushnil(L);
		}
		break;
	}
	case LUA_TNIL:
	case LUA_TTHREAD:
		lua_pushnil(L);
		break;
	default:
		luaL_error(L, "bad code");
	}
}

static int mar_decode_table(lua_State *L, int ind_cycletab, const char* buf, size_t len, size_t *idx){
	const char* p;
	p = buf;
	while(p - buf < len){
		mar_decode_value(L, ind_cycletab, buf, len, &p, idx);
		//printf("decode key "); print_item(L, -1); printf("\n");
		mar_decode_value(L, ind_cycletab, buf, len, &p, idx);
		//printf("decode val "); print_item(L, -1); printf("\n");
		if(lua_isnil(L, -2) || lua_isnil(L, -1)){
			lua_pop(L, 2);
		}else{
			lua_settable(L, -3);
		}
	}
	return 1;
}

int lua_serialize(lua_State *L, int index, mar_buffer *buf){
	size_t i;
	const int ltop = lua_gettop(L);
	if(index < 0){ index += ltop+1; }
	const size_t nitems = (size_t)(ltop+1 - index);
	
	if(index > ltop || nitems <= 0){ return -2; }
	
	lua_newtable(L); /* push table to keep track of seen values for cycle detection */
	const int ind_cycletab = lua_gettop(L);
	size_t idx = 1;
	
	buf_write_byte(L, MAR_MAGIC, buf);
	buf_write_len(L, ltop, buf);

	for(i = 0; i < nitems; ++i){
		const int ind = ltop+1-nitems+i;
		mar_encode_value(L, ind_cycletab, buf, ind, &idx);
	}
	lua_remove(L, ind_cycletab); /* pop cycle detection table */

	return 0;
}
int lua_deserialize(lua_State *L, mar_buffer *buf){
	int i;
	size_t l, idx, nitems;
	const char *p;
	const char *s = buf->data;
	l = buf->size;
	lua_settop(L, 1);

	if (l < 1) luaL_error(L, "bad header");
	if(buf_read_byte(L, &s, &l) != MAR_MAGIC) luaL_error(L, "bad magic");
	nitems = buf_read_len(L, &s, &l);

	lua_newtable(L);
	
	p = s;
	for(i = 0; i < nitems; ++i){
		mar_decode_value(L, 2, s, l, &p, &idx);
	}

	lua_remove(L, 2);

	return nitems;
}

static int mar_encode(lua_State* L){
	mar_buffer buf;
	mar_buffer_init(L, &buf);
	lua_serialize(L, 1, &buf);
	lua_pushlstring(L, buf.data, buf.head);
	mar_buffer_free(L, &buf);
	return 1;
}

static int mar_decode(lua_State* L){
	mar_buffer buf;
	buf.data = (char*)luaL_checklstring(L, 1, &buf.size);
	buf.head = 0;
	buf.seek = 0;
	return lua_deserialize(L, &buf);
}

static int mar_clone(lua_State* L){
	mar_encode(L);
	lua_replace(L, 1);
	mar_decode(L);
	return 1;
}

static const luaL_Reg R[] = {
	{"encode",      mar_encode},
	{"decode",      mar_decode},
	{"clone",       mar_clone},
	{NULL,	    NULL}
};

int luaopen_marshal(lua_State *L){
	lua_newtable(L);
	luaL_setfuncs(L, R, 0);
	return 1;
}





















static void deep_copy_1(lua_State *Lfrom, int index, lua_State *Lto, int level){
	if(level > 8){
		luaL_error(Lfrom, "Too many levels of recursion in deep copy");
	}
	switch(lua_type(Lfrom, index)){
	case LUA_TNUMBER:
		lua_pushnumber(Lto, lua_tonumber(Lfrom, index));
		break;
	case LUA_TBOOLEAN:
		lua_pushboolean(Lto, lua_toboolean(Lfrom, index));
		break;
	case LUA_TSTRING: {
		size_t length;
		const char *string = lua_tolstring(Lfrom, index, &length);
		lua_pushlstring(Lto, string, length);
		break;
	}
	case LUA_TLIGHTUSERDATA: {
		lua_pushlightuserdata(Lto, lua_touserdata(Lfrom, index));
		break;
	}
	case LUA_TNIL:
		lua_pushnil(Lto);
		break;
	case LUA_TTABLE:
		/* make sure there is room on the new state for 3 values
		 * (table,key,value) */
		if (!lua_checkstack(Lto, 3)) {
			luaL_error(Lfrom, "To stack overflow");
		}
		/* make room on from stack for key/value pairs */
		luaL_checkstack(Lfrom, 2, "From stack overflow");
		lua_newtable(Lto);
		lua_pushnil(Lfrom);
		while(lua_next(Lfrom, index) != 0){
			/* key is at (top - 1), value at (top), but we need to normalize
			 * these to positive indices */
			int kv_pos = lua_gettop(Lfrom);
			deep_copy_1(Lfrom, kv_pos - 1, Lto, level+1);
			deep_copy_1(Lfrom, kv_pos    , Lto, level+1);
			/* Copied key and value are now at -2 and -1 in dest */
			lua_settable(Lto, -3);
			/* Pop value for next iteration */
			lua_pop(Lfrom, 1);
		}
		break;
	case LUA_TFUNCTION:
	case LUA_TUSERDATA:
	case LUA_TTHREAD:
	default:
		lua_pushfstring(Lto, "Unsupported value: %s: %p",
			lua_typename(Lfrom, lua_type(Lfrom, index)),
			lua_topointer(Lfrom, index)
		);
	}
}

int deep_copy(lua_State *Lfrom, int index, lua_State *Lto, int unpack){
	if(index < 0){
		index = lua_gettop(Lfrom) + index + 1;
	}
	if(unpack){
		int i, n;
		lua_len(Lfrom, index);
		n = lua_tointeger(Lfrom, -1);
		lua_pop(Lfrom, 1);
		for(i = 0; i < n; ++i){
			lua_pushinteger(Lfrom, i+1);
			lua_gettable(Lfrom, index);
			deep_copy_1(Lfrom, lua_gettop(Lfrom), Lto, 0);
			lua_pop(Lfrom, 1);
		}
	}else{
		deep_copy_1(Lfrom, index, Lto, 0);
	}
	return 0;
}
