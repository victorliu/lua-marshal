#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <lua.h>

typedef struct mar_buffer{
	size_t size;
	size_t seek;
	size_t head;
	char*  data;
} mar_buffer;

void mar_buffer_init(lua_State *L, mar_buffer *buf);
void mar_buffer_free(lua_State *L, mar_buffer *buf);
int mar_buffer_write(lua_State* L, const char* str, size_t len, mar_buffer *buf);
const char* mar_buffer_read(lua_State *L, mar_buffer *buf, size_t *len);

/* Serializes objects on the stack into a byte stream.
 * Items on the stack at the specified index through to the top of the stack
 * are all serialized in order.
 * The output buffer should be initialized upon entry.
 */
int lua_serialize(lua_State *L, int index, mar_buffer *buf);
/* Deserializes objects in byte stream buf onto the stack.
 * Returns number of items placed on stack.
 */
int lua_deserialize(lua_State *L, mar_buffer *buf);

/* Does not check for cycles */
int lua_deepcopy(lua_State *Lfrom, int index, lua_State *Lto, int unpack);
