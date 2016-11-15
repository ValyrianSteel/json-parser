#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <memory.h>

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ('0' <= (ch) && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ('1' <= (ch) && (ch) <= '9')

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

typedef struct {
    const char* json;
    char* stack; // dynamic stack, 堆栈是以字节储存的
    size_t size, top;
} lept_context;

static void* lept_context_push(lept_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0) {
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        }
        while (c->top + size >= c->size) {
            c->size += c->size >> 1;    // c->size * 1.5
        }
        c->stack = (char*)realloc(c->stack, c->size);
    }

    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

void lept_free(lept_value* v) {
    assert(v != NULL);
    size_t i;
    switch (v->type) {
        case LEPT_STRING:
            free(v->s.s);
            break;
        case LEPT_ARRAY: // 应该先把数组内的元素通过递归调用 lept_free() 释放，然后才释放本身的 v->a.e
            for (i = 0; i < v->a.size; i++) {
                lept_free(&v->a.e[i]);
            }
            free(v->a.e);
            break;
        case LEPT_OBJECT:
            for (i = 0; i < v->o.size; i++) {
                free(v->o.m[i].k);
                lept_free(&v->o.m[i].v);
            }
            free(v->o.m);
            break;
        default:
            break;
    }
    v->type = LEPT_NULL; // 避免重复释放
}


static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}


lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}


static int lept_parse_value(lept_context* c, lept_value* v);


// null, true, false

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b) {
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

static int lept_parse_literal(lept_context* c, lept_value* v,
                                const char* literal, lept_type type)
{
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i+1]; i++) {
        if (c->json[i] != literal[i+1]) {
            return LEPT_PARSE_INVALID_VALUE;
        }
    }
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}


// number

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}

void lept_set_number(lept_value* v, double n) {
    lept_free(v);
    v->n = n;
    v->type = LEPT_NUMBER;
}

static int lept_parse_number(lept_context* c, lept_value* v) {
    // validate number
    const char* p = c->json;
    if (*p == '-') p++;
    if (*p == '0') {
        p++;
//        if (ISDIGIT1TO9(*p) || *p == 'x' || *p == 'X') return LEPT_PARSE_ROOT_NOT_SINGULAR;
    } else {
        if (!ISDIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
        for(p++; ISDIGIT(*p); p++);
    }
    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    errno = 0;

    // double      strtod( const char *restrict str, char **restrict str_end );
    v->n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL)) {
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }

    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}


// string

const char* lept_get_string(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->s.s;
}

size_t lept_get_string_length(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->s.len;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->s.s = (char*)malloc(len + 1);
    memcpy(v->s.s, s, len);
    v->s.s[len] = '\0';
    v->s.len = len;
    v->type = LEPT_STRING;
}


#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)
#define PUTC(c, ch) do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

static const char* lept_parse_hex4(const char* p, unsigned* u) {
    int i;
    *u = 0;
    for (i = 0; i < 4; i++) {
        char ch = *p++;
        *u <<= 4;
        if (ch >= '0' && ch <= '9') *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F') *u |= ch - ('A' - 10);
        else if (ch >= 'a' && ch <= 'f') *u |= ch - ('a' - 10);
        else return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned u) {
    if (u <= 0x7F) {
        PUTC(c, u & 0xFF);
    } else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(c, 0x80 | ( u       & 0x3F));
    } else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    } else {
        assert(u <= 0x10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

// 解析字符串:先备份栈顶，然后把解析到的字符压栈，最后计算出长度并一次性把所有字符弹出，再设置至值里。
static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
    size_t head = c->top;
    unsigned u, u2;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *len = c->top - head;
                *str = lept_context_pop(c, *len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\\':
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/' ); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = lept_parse_hex4(p, &u))) {
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        }
                        if (u >= 0xD800 && u <= 0xDBFF) { /* surrogate pair */
                            if (*p++ != '\\')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = lept_parse_hex4(p, &u2)))
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\0':
                STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20) {
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                }
                PUTC(c, ch);
        }
    }
}

static int lept_parse_string(lept_context* c, lept_value* v) {
    int ret;
    char* s;
    size_t len;
    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK) {
        lept_set_string(v, s, len);
    }
    return ret;
}

// array = %x5B ws [ value *( ws %x2C ws value ) ] ws %x5D

size_t lept_get_array_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->a.size;
}

lept_value* lept_get_array_element(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->a.size);
    return &v->a.e[index];
}

// 和字符串有点不一样，如果把 JSON 当作一棵树的数据结构，JSON 字符串是叶节点，而 JSON 数组是中间节点。
// 在叶节点的解析函数中，我们怎样使用那个堆栈也可以，只要最后还原就好了。
// 但对于数组这样的中间节点，只要在解析函数结束时还原堆栈的状态，就没有问题。
static int lept_parse_array(lept_context* c, lept_value* v) {
    size_t size = 0;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        v->type = LEPT_ARRAY;
        v->a.size = 0;
        v->a.e = NULL;
        return LEPT_PARSE_OK;
    }
    for (;;) {
        lept_value e;
        lept_init(&e);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK) {
            break;
        }
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;

        lept_parse_whitespace(c);

        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else if (*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->a.size = size;
            size *= sizeof(lept_value);
            memcpy(v->a.e = (lept_value*)malloc(size), lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }

    /* Pop and free values on the stack */
    size_t i;
    for (i = 0; i < size; i++) {
        lept_free((lept_value *) lept_context_pop(c, sizeof(lept_value)));
    }

    return ret;
}


// object

size_t lept_get_object_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->o.size;
}

const char* lept_get_object_key(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->o.size);
    return v->o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index){
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->o.size);
    return v->o.m[index].klen;
}

lept_value* lept_get_object_value(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->o.size);
    return &v->o.m[index].v;
}

static int lept_parse_object(lept_context* c, lept_value* v) {
    size_t i, size;
    lept_member m;
    int ret;
    EXPECT(c,'{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        v->type = LEPT_OBJECT;
        v->o.m = 0;
        v->o.size = 0;
        return LEPT_PARSE_OK;
    }
    m.k = NULL;
    size = 0;
    for (;;) {
        char* str;
        lept_init(&m.v);

        // parse key
        if (*c->json != '"') {
            ret  = LEPT_PARSE_MISS_KEY;
            break;
        }
        if ((ret = lept_parse_string_raw(c, &str, &m.klen)) != LEPT_PARSE_OK) {
            break;
        }
        memcpy(m.k = (char*)malloc(m.klen + 1), str, m.klen + 1);

        // parse ws colon ws
        lept_parse_whitespace(c);
        if (*c->json != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        lept_parse_whitespace(c);

        // parse value
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK) {
            break;
        }
        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.k = NULL;

        // parse ws [comma | right-curly-brace] ws
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else if (*c->json == '}') {
            size_t s = sizeof(lept_member) * size;
            c->json++;
            v->type = LEPT_OBJECT;
            v->o.size = size;
            memcpy(v->o.m = (lept_member*)malloc(s), lept_context_pop(c, s), s);
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }

    // pop and free members on the stack
    free(m.k);
    for (i = 0; i < size; i++) {
        lept_member* m = (lept_member*)lept_context_pop(c, sizeof(lept_member));
        free(m->k);
        lept_free(&m->v);
    }
    v->type = LEPT_NULL;
    return ret;
}


static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 'n':  return lept_parse_literal(c, v, "null", LEPT_NULL);
        case 't':  return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f':  return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case '"':  return lept_parse_string(c, v);
        case '[':  return lept_parse_array(c, v);
        case '{':  return lept_parse_object(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
        default:   return lept_parse_number(c, v);
    }
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL; c.size = c.top = 0; // init stack
    v->type = LEPT_NULL;

    lept_init(v);
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;  // parse number not singular: if (ISDIGIT1TO9(*p) || *p == 'x' || *p == 'X') return LEPT_PARSE_ROOT_NOT_SINGULAR;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }

    assert(c.top == 0); free(c.stack); // free stack

    return ret;
}
