#if 1 /* patchouli vrio-trace */
#ifndef _TRACE_H
#define _TRACE_H

#include <linux/jiffies.h>

#include <linux/socket.h>
#include <linux/netdevice.h> // for dev_put()
#include <net/sock.h>

#include <linux/sched.h>

#include "version.h"

#define TRACE_ENABLED        1
#define TRACE_DEBUG          (TRACE_ENABLED && 1)

#if !TRACE_ENABLED
#undef TRACE
#define TRACE 0
#endif

#define TRACE_LEVEL_ERRORS   1
#define TRACE_LEVEL_MESSAGES 2
#define TRACE_LEVEL_NOTICES  3
#define TRACE_LEVEL_ALL      4  

#ifndef TRACE_LEVEL
#define TRACE_LEVEL          3 // TRACE_LEVEL_NOTICES
#endif

#define HEX_SUPPORT          1
#define HEX_MAX_SIZE         128 // 16384
#define SUPPRESS_UNUSED      __attribute__ ((unused))
        
typedef enum {TYPE_INCLUDE, TYPE_EXCLUDE} trace_list_type;

#define TRACE_ALL \
        static const char SUPPRESS_UNUSED **trace_list = NULL;

#define	TRACE_ERRORS_ONLY \
        static const char SUPPRESS_UNUSED *trace_list[] = {((void *)TYPE_INCLUDE), NULL};

#define	TRACE_INCLUDE(args...) \
        static const char SUPPRESS_UNUSED *trace_list[] = {((void *)TYPE_INCLUDE), ##args, NULL};

#define	TRACE_EXCLUDE(args...) \
        static const char SUPPRESS_UNUSED *trace_list[] = {((void *)TYPE_EXCLUDE), ##args, NULL};

#ifndef TRACE
#define TRACE 1
#endif

#define __SHORT_FORM_OF_FILE__ \
 (strrchr(__FILE__,'/') \
 ? strrchr(__FILE__,'/')+1 \
 : __FILE__ \
 )

#define __trace(fmt, trace_list, args...) \
            tprintk(__SHORT_FORM_OF_FILE__, __func__, trace_list, fmt, ##args)

#include "debug.h"

#if TRACE

#if TRACE_LEVEL >= TRACE_LEVEL_ERRORS
#define etrace(fmt, args...) \
        __trace("ERROR(%d): "fmt, NULL, __LINE__, ##args)

#define atrace(condition, ...) { \
            if (condition) { \
                __trace("ASSERT ON LINE: %d (%s)", NULL,  __LINE__, #condition); \
                __VA_ARGS__; \
            } \
        }

#define strace() dump_stack()
#else
#define etrace(fmt, args...) 
#define atrace(condition) 
#define strace()
#endif

#if TRACE_LEVEL >= TRACE_LEVEL_MESSAGES
#define mtrace(fmt, args...) \
        __trace("MESSAGE: "fmt, trace_list, ##args)
#else
#define mtrace(fmt, args...)
#endif

#if TRACE_LEVEL >= TRACE_LEVEL_NOTICES
#define ntrace(fmt, args...) \
        __trace("NOTICE: "fmt, trace_list, ##args)
#else
#define ntrace(fmt, args...)
#endif

#if TRACE_LEVEL >= TRACE_LEVEL_ALL
#define trace(fmt, args...) \
        __trace(fmt, trace_list, ##args)
#else
#define trace(fmt, args...)
#endif

#else 

#define trace(fmt, args...)
#define mtrace(fmt, args...) \
    printk("[vrio #%d] <%s/%s> _MESSAGE: "fmt"\n", VRIO_BUILD_NUM, __SHORT_FORM_OF_FILE__, __func__, ##args)
#define ntrace(fmt, args...)
#define etrace(fmt, args...) \
    printk("[vrio #%d] <%s/%s> _ERROR: "fmt"\n", VRIO_BUILD_NUM, __SHORT_FORM_OF_FILE__, __func__, ##args)

#define atrace(condition, ...) 
#define strace()
#endif

#if TRACE

#define NIPQUAD(addr) \
    (int)((unsigned char *)&addr)[0], \
    (int)((unsigned char *)&addr)[1], \
    (int)((unsigned char *)&addr)[2], \
    (int)((unsigned char *)&addr)[3]

#define BUFF_SIZE 65536
static char nibble2hex[17] = "0123456789ABCDEF";

static int tvsprintf(char *buf, const char *fmt, va_list args);
static int tsprintf(char *buf, const char *fmt, ...);

static void SUPPRESS_UNUSED tprintk(const char *file_name, const char *func_name,
                            const char *trace_list[], const char *fmt, ...)
{
    int len;
    static char tbuff[BUFF_SIZE];
    static char kbuff[BUFF_SIZE];
    static spinlock_t lock;
    static bool spinlock_initialized = false;
    unsigned long flags;
    va_list args;

    if (!spinlock_initialized) {
        spinlock_initialized = true;
        spin_lock_init(&lock);
    }

    if (trace_list) {
        trace_list_type type = ((trace_list_type)trace_list[0]);
        trace_list++;

        while (*trace_list) {
            if (strnicmp(func_name, *trace_list, strlen(func_name)) == 0)
                break;
            trace_list++;
        }

        if (*trace_list == NULL && type == TYPE_INCLUDE)
            return;

        if (*trace_list != NULL && type == TYPE_EXCLUDE)
            return;
    }

    spin_lock_irqsave(&lock, flags);
    va_start(args, fmt);
    
    tvsprintf(tbuff, fmt, args);
    len = tsprintf(kbuff, "[vrio #%d, %d] <%s/%s> %s\n", VRIO_BUILD_NUM, task_cpu(current), file_name, func_name, tbuff);
    printk(kbuff);
    
    va_end(args);
    spin_unlock_irqrestore(&lock, flags);
}

static int skip_atoi(const char **s)
{
    int i, c;

    for (i = 0; '0' <= (c = **s) && c <= '9'; ++*s)
        i = i*10 + c - '0';
    return i;
}

#define ZEROPAD	1		/* pad with zero */
#define SIGN	2		/* unsigned/signed long */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define LEFT	16		/* left justified */
#define SPECIAL	32		/* 0x */
#define LARGE	64		/* use 'ABCDEF' instead of 'abcdef' */

static char *number(char * str, unsigned long long num, int base, int size, int precision, int type)
{
    char c,sign,tmp[66];
    const char *digits="0123456789abcdefghijklmnopqrstuvwxyz";
    int i;

    if (type & LARGE)
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (type & LEFT)
        type &= ~ZEROPAD;
    if (base < 2 || base > 36)
        return 0;
    c = (type & ZEROPAD) ? '0' : ' ';
    sign = 0;
    if (type & SIGN) {
        if ((signed long long)num < 0) {
            sign = '-';
            num = - (signed long long)num;
            size--;
        } else if (type & PLUS) {
            sign = '+';
            size--;
        } else if (type & SPACE) {
            sign = ' ';
            size--;
        }
    }
    if (type & SPECIAL) {
        if (base == 16)
            size -= 2;
        else if (base == 8)
            size--;
    }
    i = 0;
    if (num == 0)
        tmp[i++]='0';
    else while (num != 0) {
        tmp[i++] = digits[do_div(num, base)];
    }
    if (i > precision)
        precision = i;
    size -= precision;
    if (!(type&(ZEROPAD+LEFT)))
        while(size-->0)
            *str++ = ' ';
    if (sign)
        *str++ = sign;
    if (type & SPECIAL) {
        if (base==8)
            *str++ = '0';
        else if (base==16) {
            *str++ = '0';
            *str++ = digits[33];
        }
    }
    if (!(type & LEFT))
        while (size-- > 0)
            *str++ = c;
    while (i < precision--)
        *str++ = '0';
    while (i-- > 0)
        *str++ = tmp[i];
    while (size-- > 0)
        *str++ = ' ';
    return str;
}

int tsprintf(char *buf, const char *fmt, ...)
{
    va_list args;
    int i;

    va_start(args, fmt);
    i = tvsprintf(buf, fmt, args);
    va_end(args);

    return i;
}

static int tvsprintf(char *buf, const char *fmt, va_list args)
{
    int len;
    unsigned long long num;
    int i, base;
    char * str;
    const char *s;

    int flags;		/* flags to number() */

    int field_width;	/* width of output field */
    int precision;		/* min. # of digits for integers; max
                   number of chars for from string */
    int qualifier;		/* 'h', 'l', or 'L' for integer fields */
                            /* 'z' support added 23/7/1999 S.H.    */
                /* 'z' changed to 'Z' --davidm 1/25/99 */

    
    for (str=buf ; *fmt ; ++fmt) {
        if (*fmt != '%') {
            *str++ = *fmt;
            continue;
        }
            
        /* process flags */
        flags = 0;
        repeat:
            ++fmt;		/* this also skips first '%' */
            switch (*fmt) {
                case '-': flags |= LEFT; goto repeat;
                case '+': flags |= PLUS; goto repeat;
                case ' ': flags |= SPACE; goto repeat;
                case '#': flags |= SPECIAL; goto repeat;
                case '0': flags |= ZEROPAD; goto repeat;
                }
        
        /* get field width */
        field_width = -1;
        if ('0' <= *fmt && *fmt <= '9')
            field_width = skip_atoi(&fmt);
        else if (*fmt == '*') {
            ++fmt;
            /* it's the next argument */
            field_width = va_arg(args, int);
            if (field_width < 0) {
                field_width = -field_width;
                flags |= LEFT;
            }
        }

        /* get the precision */
        precision = -1;
        if (*fmt == '.') {
            ++fmt;	
            if ('0' <= *fmt && *fmt <= '9')
                precision = skip_atoi(&fmt);
            else if (*fmt == '*') {
                ++fmt;
                /* it's the next argument */
                precision = va_arg(args, int);
            }
            if (precision < 0)
                precision = 0;
        }

        /* get the conversion qualifier */
        qualifier = -1;
        if (*fmt == 'l' && *(fmt + 1) == 'l') {
            qualifier = 'q';
            fmt += 2;
        } else if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L'
            || *fmt == 'Z') {
            qualifier = *fmt;
            ++fmt;
        }

        /* default base */
        base = 10;

        switch (*fmt) {
        case 'c':
            if (!(flags & LEFT))
                while (--field_width > 0)
                    *str++ = ' ';
            *str++ = (unsigned char) va_arg(args, int);
            while (--field_width > 0)
                *str++ = ' ';
            continue;

        case 'b':
            s = va_arg(args, char *);
#if !HEX_SUPPORT
            s = NULL;
#endif
            if (!s) {
                s = "<NULL>";
                len = 7;
                for (i = 0; i < len; ++i)
                    *str++ = *s++;
                continue;
            }

            len = min(HEX_MAX_SIZE, precision);
            for (i = 0; i < len; ++i, ++s) {     
                *str++ = nibble2hex[(*s >> 4) & 0xF];
                *str++ = nibble2hex[*s & 0xF];
            }
            continue;
        case 's':
            s = va_arg(args, char *);
            if (!s)
                s = "<NULL>";

            len = strnlen(s, precision);

            if (!(flags & LEFT))
                while (len < field_width--)
                    *str++ = ' ';
            for (i = 0; i < len; ++i)
                *str++ = *s++;
            while (len < field_width--)
                *str++ = ' ';
            continue;
        case 'p':
            if (field_width == -1) {
                field_width = 2*sizeof(void *);
                flags |= ZEROPAD;
            }
            str = number(str,
                (unsigned long) va_arg(args, void *), 16,
                field_width, precision, flags);
            continue;


        case 'n':
            if (qualifier == 'l') {
                long * ip = va_arg(args, long *);
                *ip = (str - buf);
            } else if (qualifier == 'Z') {
                size_t * ip = va_arg(args, size_t *);
                *ip = (str - buf);
            } else {
                int * ip = va_arg(args, int *);
                *ip = (str - buf);
            }
            continue;

        case '%':
            *str++ = '%';
            continue;

        /* integer number formats - set up the flags and "break" */
        case 'o':
            base = 8;
            break;

        case 'X':
            flags |= LARGE;
        case 'x':
            base = 16;
            break;

        case 'd':
        case 'i':
            flags |= SIGN;
        case 'u':
            break;

        default:
            *str++ = '%';
            if (*fmt)
                *str++ = *fmt;
            else
                --fmt;
            continue;
        }
        if (qualifier == 'l') {
            num = va_arg(args, unsigned long);
            if (flags & SIGN)
                num = (signed long) num;
        } else if (qualifier == 'q') {
            num = va_arg(args, unsigned long long);
            if (flags & SIGN)
                num = (signed long long) num;
        } else if (qualifier == 'Z') {
            num = va_arg(args, size_t);
        } else if (qualifier == 'h') {
            num = (unsigned short) va_arg(args, int);
            if (flags & SIGN)
                num = (signed short) num;
        } else {
            num = va_arg(args, unsigned int);
            if (flags & SIGN)
                num = (signed int) num;
        }
        str = number(str, num, base, field_width, precision, flags);
    }
    *str = '\0';
    return str-buf;
}

#endif

#endif /* _TRACE_H */
#endif 
