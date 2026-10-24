/* Opt-in, offline SKProductsRequest catalogue companion for LocalIAPStore.
 * The transaction and receipt paths remain owned by LocalIAPStore. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void *Obj;
typedef void *Sel;
typedef void *Cls;
typedef void *Method;

extern Cls objc_getClass(const char *);
extern Cls object_getClass(Obj);
extern Cls objc_allocateClassPair(Cls, const char *, size_t);
extern void objc_registerClassPair(Cls);
extern int class_addMethod(Cls, Sel, void *, const char *);
extern Sel sel_registerName(const char *);
extern Obj objc_msgSend(Obj, Sel, ...);
extern void objc_setAssociatedObject(Obj, const void *, Obj, unsigned long);
extern Obj objc_getAssociatedObject(Obj, const void *);
extern void MSHookMessageEx(Cls, Sel, void *, void **);
extern void syslog(int, const char *, ...);

static char kIdentifiers, kTitle, kProducts, kInvalid;
static Obj configuration;
static int configuration_attempted;
static int automatic_products;
static Cls product_class, response_class;
static Obj (*original_init)(Obj, Sel, Obj);
static void (*original_start)(Obj, Sel);
static void (*original_game_start)(Obj, Sel);
static void (*original_verify_purchase)(Obj, Sel, Obj, Obj);
static void (*original_jetpack_add_payment)(Obj, Sel, Obj);
static void (*original_jetpack_updated)(Obj, Sel, Obj, Obj);
static void (*original_ski_updated)(Obj, Sel, Obj, Obj);
static Obj (*original_legacy_receipt)(Obj, Sel);
static unsigned char (*original_zombie_receipt_status)(Obj, Sel, Obj);
static Obj jetpack_pending_product;
static int jetpack_purchase_delivered;
static Obj ski_seen_transactions;
static Obj seen_transaction_ids;
static int ski_mode;
static int jetpack_mode;
static int zombie_mode;
static Obj zombie_pending_product;
static int zombie_receipt_ready;
static int legacy_receipt_hooked;
static void install_legacy_receipt_hook(void);
static void (*original_add_observer)(Obj, Sel, Obj);
static void (*original_queue_add_payment)(Obj, Sel, Obj);
typedef void (*UpdatedTransactions)(Obj, Sel, Obj, Obj);
static struct {
    Cls klass;
    UpdatedTransactions original;
} observer_hooks[32];
static unsigned observer_hook_count;

typedef struct {
    void *isa;
    int flags;
    int reserved;
    void (*invoke)(void *, Obj, int);
    void *descriptor;
} PurchaseCompletion;

static Sel selector(const char *name) { return sel_registerName(name); }
static Obj send0(Obj receiver, const char *name) {
    return ((Obj (*)(Obj, Sel))objc_msgSend)(receiver, selector(name));
}
static Obj send1(Obj receiver, const char *name, Obj argument) {
    return ((Obj (*)(Obj, Sel, Obj))objc_msgSend)(receiver, selector(name), argument);
}
static Obj string(const char *value) {
    return send1((Obj)objc_getClass("NSString"), "stringWithUTF8String:", (Obj)value);
}
static const char *utf8(Obj value) {
    if (!value) return "(nil)";
    const char *result = (const char *)send0(value, "UTF8String");
    return result ? result : "(unprintable)";
}
static void associate(Obj object, const void *key, Obj value) {
    objc_setAssociatedObject(object, key, value, 1); /* retain, nonatomic */
}
static Obj dictionary_value(Obj dict, Obj key) {
    return dict ? send1(dict, "objectForKey:", key) : NULL;
}

static void load_configuration(void) {
    if (configuration_attempted) return;
    configuration_attempted = 1;
    Obj main_bundle = send0((Obj)objc_getClass("NSBundle"), "mainBundle");
    Obj bundle = send0(main_bundle, "bundleIdentifier");
    Obj path = send0(main_bundle, "bundlePath");
    /* Never synthesize StoreKit metadata inside an Apple/system process. */
    if (!bundle || !path || !((int (*)(Obj, Sel, Obj))objc_msgSend)(path,
            selector("hasPrefix:"), string("/var/mobile/Applications/"))) return;
    ski_mode = !strcmp(utf8(bundle), "com.DefiantDev.SkiSafari");
    jetpack_mode = !strcmp(utf8(bundle), "com.halfbrick.jetpack");
    zombie_mode = !strcmp(utf8(bundle), "net.mobigame.ZombieCarnaval");
    Obj config = send1((Obj)objc_getClass("NSDictionary"), "dictionaryWithContentsOfFile:",
        string("/Library/Preferences/LocalAPStoreOfflineCatalog.plist"));
    Obj excluded = dictionary_value(config, string("ExcludedBundles"));
    if (excluded && ((int (*)(Obj, Sel, Obj))objc_msgSend)(excluded,
            selector("containsObject:"), bundle)) return;
    automatic_products = (int)(size_t)send0(
        dictionary_value(config, string("AutomaticProducts")), "boolValue");
    Obj candidate = dictionary_value(config, bundle);
    if (candidate && send0(dictionary_value(candidate, string("Enabled")), "boolValue"))
        configuration = send0(candidate, "retain");
    if (automatic_products || configuration)
        syslog(5, "LocalAPStoreOffline enabled for %s (automatic=%d)",
               utf8(bundle), automatic_products);
}

static Obj product_identifier(Obj self, Sel unused) {
    (void)unused;
    return objc_getAssociatedObject(self, &kIdentifiers);
}
static Obj product_title(Obj self, Sel unused) {
    (void)unused;
    return objc_getAssociatedObject(self, &kTitle);
}
static Obj product_price(Obj self, Sel unused) {
    (void)self; (void)unused;
    return send1((Obj)objc_getClass("NSDecimalNumber"), "decimalNumberWithString:", string("0.00"));
}
static Obj product_locale(Obj self, Sel unused) {
    (void)self; (void)unused;
    Obj locale_class = (Obj)objc_getClass("NSLocale");
    Obj current = send0(locale_class, "currentLocale");
    Obj code = send1(current, "objectForKey:", string("currency"));
    Obj identifier = send0(current, "localeIdentifier");
    if (!code || !identifier) return send1(locale_class, "localeWithLocaleIdentifier:",
                                           string("en_US@currency=USD"));
    Obj parts = send1(identifier, "componentsSeparatedByString:", string("@"));
    /* Use the longstanding indexed accessor on legacy Foundation runtimes. */
    Obj base = (size_t)send0(parts, "count") ?
        ((Obj (*)(Obj, Sel, unsigned))objc_msgSend)(parts, selector("objectAtIndex:"), 0) :
        identifier;
    Obj prefix = send1(base, "stringByAppendingString:", string("@currency="));
    Obj full = send1(prefix, "stringByAppendingString:", code);
    return send1(locale_class, "localeWithLocaleIdentifier:", full);
}
static int product_not_downloadable(Obj self, Sel unused) {
    (void)self; (void)unused;
    return 0;
}
static Obj response_products(Obj self, Sel unused) {
    (void)unused;
    return objc_getAssociatedObject(self, &kProducts);
}
static Obj response_invalid(Obj self, Sel unused) {
    (void)unused;
    return objc_getAssociatedObject(self, &kInvalid);
}

static Obj configured_title(Obj identifier) {
    Obj known = dictionary_value(configuration, string("ProductIDs"));
    Obj title = dictionary_value(known, identifier);
    if (title) return title;
    Obj files = dictionary_value(configuration, string("CatalogPlists"));
    Obj bundle_path = send0(send0((Obj)objc_getClass("NSBundle"), "mainBundle"), "bundlePath");
    unsigned count = (unsigned)(size_t)send0(files, "count");
    for (unsigned i = 0; i < count; ++i) {
        Obj file = ((Obj (*)(Obj, Sel, unsigned))objc_msgSend)(files, selector("objectAtIndex:"), i);
        Obj path = send1(bundle_path, "stringByAppendingPathComponent:", file);
        Obj plist = send1((Obj)objc_getClass("NSDictionary"), "dictionaryWithContentsOfFile:", path);
        Obj ids = dictionary_value(plist, string("Identifiers"));
        Obj keys = send0(ids, "allKeys");
        unsigned key_count = (unsigned)(size_t)send0(keys, "count");
        for (unsigned j = 0; j < key_count; ++j) {
            Obj key = ((Obj (*)(Obj, Sel, unsigned))objc_msgSend)(keys, selector("objectAtIndex:"), j);
            Obj value = dictionary_value(ids, key);
            if (((int (*)(Obj, Sel, Obj))objc_msgSend)(identifier, selector("isEqualToString:"), value))
                return key;
        }
    }
    return NULL;
}

static Obj catalogue_title(Obj identifier) {
    Obj title = configured_title(identifier);
    if (title || !automatic_products || !identifier) return title;
    Obj components = send1(identifier, "componentsSeparatedByString:", string("."));
    title = send0(components, "lastObject");
    return (size_t)send0(title, "length") ? title : identifier;
}

static Obj make_product(Obj identifier, Obj title) {
    Obj product = send0(send0((Obj)product_class, "alloc"), "init");
    if (!product) return NULL;
    associate(product, &kIdentifiers, identifier);
    associate(product, &kTitle, title);
    return send0(product, "autorelease");
}

static void deliver(Obj request, Sel unused, Obj argument) {
    (void)unused; (void)argument;
    Obj identifiers = objc_getAssociatedObject(request, &kIdentifiers);
    Obj products = send0((Obj)objc_getClass("NSMutableArray"), "array");
    Obj invalid = send0((Obj)objc_getClass("NSMutableArray"), "array");
    Obj all = send0(identifiers, "allObjects");
    unsigned count = (unsigned)(size_t)send0(all, "count");
    for (unsigned i = 0; i < count; ++i) {
        Obj identifier = ((Obj (*)(Obj, Sel, unsigned))objc_msgSend)(all, selector("objectAtIndex:"), i);
        Obj title = catalogue_title(identifier);
        if (title) {
            Obj product = make_product(identifier, title);
            if (product) send1(products, "addObject:", product);
        } else {
            send1(invalid, "addObject:", identifier);
        }
    }
    Obj response = send0(send0((Obj)response_class, "alloc"), "init");
    associate(response, &kProducts, products);
    associate(response, &kInvalid, invalid);
    Obj delegate = send0(request, "delegate");
    if (delegate) {
        ((void (*)(Obj, Sel, Obj, Obj))objc_msgSend)(delegate,
            selector("productsRequest:didReceiveResponse:"), request, response);
        Sel finished = selector("requestDidFinish:");
        if (((int (*)(Obj, Sel, Sel))objc_msgSend)(delegate,
                selector("respondsToSelector:"), finished))
            ((void (*)(Obj, Sel, Obj))objc_msgSend)(delegate, finished, request);
    }
    send0(response, "release");
    syslog(5, "LocalAPStoreOffline delivered %u products, %u unknown IDs",
           (unsigned)(size_t)send0(products, "count"),
           (unsigned)(size_t)send0(invalid, "count"));
}

static Obj replacement_init(Obj self, Sel cmd, Obj identifiers) {
    Obj request = original_init(self, cmd, identifiers);
    if (request && identifiers) associate(request, &kIdentifiers, identifiers);
    return request;
}

static int offline_request(Obj request) {
    load_configuration();
    install_legacy_receipt_hook();
    Obj identifiers = objc_getAssociatedObject(request, &kIdentifiers);
    if ((!configuration && !automatic_products) || !identifiers ||
        !(size_t)send0(identifiers, "count")) {
        return 0;
    }
    Obj all = send0(identifiers, "allObjects");
    unsigned count = (unsigned)(size_t)send0(all, "count");
    unsigned known = 0;
    for (unsigned i = 0; i < count; ++i) {
        Obj identifier = ((Obj (*)(Obj, Sel, unsigned))objc_msgSend)(all, selector("objectAtIndex:"), i);
        if (catalogue_title(identifier)) ++known;
    }
    /* Unknown requests retain their original StoreKit behaviour. */
    if (known != count) {
        syslog(5, "LocalAPStoreOffline pass-through: %u of %u IDs catalogued",
               known, count);
        return 0;
    }
    ((void (*)(Obj, Sel, Sel, Obj, double))objc_msgSend)(request,
        selector("performSelector:withObject:afterDelay:"),
        selector("lap_deliverOffline:"), NULL, 0.0);
    syslog(5, "LocalAPStoreOffline queued %u catalogued IDs", count);
    return 1;
}

static void replacement_start(Obj self, Sel cmd) {
    if (!offline_request(self)) original_start(self, cmd);
}
static void replacement_game_start(Obj self, Sel cmd) {
    if (!offline_request(self)) original_game_start(self, cmd);
}

static void replacement_verify_purchase(Obj self, Sel cmd, Obj transaction, Obj completion) {
    load_configuration();
    Obj bundle = send0(send0((Obj)objc_getClass("NSBundle"), "mainBundle"), "bundleIdentifier");
    if (!configuration || strcmp(utf8(bundle), "com.gameprom.software.PinballHD") ||
        !transaction || !completion ||
        !((int (*)(Obj, Sel, Sel))objc_msgSend)(transaction, selector("respondsToSelector:"),
            selector("transactionState"))) {
        original_verify_purchase(self, cmd, transaction, completion);
        return;
    }
    Obj payment = send0(transaction, "payment");
    Obj identifier = send0(payment, "productIdentifier");
    int state = (int)(size_t)send0(transaction, "transactionState");
    if (state == 1 && configured_title(identifier)) {
        syslog(5, "LocalAPStoreOffline accepted local purchased transaction for %s", utf8(identifier));
        ((PurchaseCompletion *)completion)->invoke(completion, transaction, 1);
        return;
    }
    original_verify_purchase(self, cmd, transaction, completion);
}

static void replacement_jetpack_add_payment(Obj self, Sel cmd, Obj payment) {
    load_configuration();
    if (!jetpack_mode) {
        original_jetpack_add_payment(self, cmd, payment);
        return;
    }
    Obj identifier = send0(payment, "productIdentifier");
    send0(jetpack_pending_product, "release");
    jetpack_pending_product = send0(identifier, "retain");
    jetpack_purchase_delivered = 0;
    original_jetpack_add_payment(self, cmd, payment);
}

static void replacement_jetpack_updated(Obj self, Sel cmd, Obj queue, Obj transactions) {
    load_configuration();
    if (!jetpack_mode) {
        original_jetpack_updated(self, cmd, queue, transactions);
        return;
    }
    Obj forwarded = send0((Obj)objc_getClass("NSMutableArray"), "array");
    unsigned count = (unsigned)(size_t)send0(transactions, "count");
    for (unsigned i = 0; i < count; ++i) {
        Obj transaction = ((Obj (*)(Obj, Sel, unsigned))objc_msgSend)(
            transactions, selector("objectAtIndex:"), i);
        Obj payment = send0(transaction, "payment");
        Obj identifier = send0(payment, "productIdentifier");
        int same_product = jetpack_pending_product && identifier &&
            ((int (*)(Obj, Sel, Obj))objc_msgSend)(identifier,
                selector("isEqualToString:"), jetpack_pending_product);
        int purchased = (int)(size_t)send0(transaction, "transactionState") == 1;
        if (same_product && purchased) {
            Obj transaction_id = send0(transaction, "transactionIdentifier");
            if (!transaction_id || jetpack_purchase_delivered) {
                /* LocalIAPStore can emit two unnumbered purchased callbacks
                 * before the numbered transaction. Jetpack awards coins for
                 * each callback, so finish the duplicates without forwarding. */
                send1(queue, "finishTransaction:", transaction);
                syslog(5, "LocalAPStoreOffline discarded duplicate Jetpack transaction");
                continue;
            }
            jetpack_purchase_delivered = 1;
        }
        send1(forwarded, "addObject:", transaction);
    }
    if ((size_t)send0(forwarded, "count"))
        original_jetpack_updated(self, cmd, queue, forwarded);
}

static int base64_digit(char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

static char *base64_decode(const char *input, size_t *decoded_size) {
    size_t length = strlen(input);
    char *result = malloc(length * 3 / 4 + 4);
    if (!result) return NULL;
    unsigned value = 0, bits = 0;
    size_t size = 0;
    for (size_t i = 0; i < length && input[i] != '='; ++i) {
        int digit = base64_digit(input[i]);
        if (digit < 0) { free(result); return NULL; }
        value = (value << 6) | (unsigned)digit;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result[size++] = (char)(value >> bits);
        }
    }
    result[size] = 0;
    *decoded_size = size;
    return result;
}

static char *base64_encode(const char *input, size_t length) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *result = malloc(((length + 2) / 3) * 4 + 1);
    if (!result) return NULL;
    size_t output = 0;
    for (size_t i = 0; i < length; i += 3) {
        unsigned bytes = (unsigned)(unsigned char)input[i] << 16;
        if (i + 1 < length) bytes |= (unsigned)(unsigned char)input[i + 1] << 8;
        if (i + 2 < length) bytes |= (unsigned)(unsigned char)input[i + 2];
        result[output++] = alphabet[(bytes >> 18) & 63];
        result[output++] = alphabet[(bytes >> 12) & 63];
        result[output++] = i + 1 < length ? alphabet[(bytes >> 6) & 63] : '=';
        result[output++] = i + 2 < length ? alphabet[bytes & 63] : '=';
    }
    result[output] = 0;
    return result;
}

static int field_bounds(char *document, const char *key, char **start, char **end) {
    size_t key_length = strlen(key);
    char *marker = malloc(key_length + 3);
    if (!marker) return 0;
    marker[0] = '"';
    memcpy(marker + 1, key, key_length);
    marker[key_length + 1] = '"';
    marker[key_length + 2] = 0;
    char *at = strstr(document, marker);
    free(marker);
    if (!at) return 0;
    at += key_length + 2;
    while (*at == ' ' || *at == '\t' || *at == '\r' || *at == '\n') ++at;
    if (*at++ != '=') return 0;
    while (*at == ' ' || *at == '\t' || *at == '\r' || *at == '\n') ++at;
    if (*at++ != '"') return 0;
    *start = at;
    while (*at && *at != '"') ++at;
    if (*at != '"') return 0;
    *end = at;
    return 1;
}

static char *copy_field(char *document, const char *key) {
    char *start, *end;
    if (!field_bounds(document, key, &start, &end)) return NULL;
    size_t length = (size_t)(end - start);
    char *result = malloc(length + 1);
    if (!result) return NULL;
    memcpy(result, start, length);
    result[length] = 0;
    return result;
}

static char *replace_field(char *document, const char *key, const char *value) {
    char *start, *end;
    if (!document || !value || !field_bounds(document, key, &start, &end)) return NULL;
    size_t before = (size_t)(start - document);
    size_t after = strlen(end);
    size_t replacement = strlen(value);
    char *result = malloc(before + replacement + after + 1);
    if (!result) return NULL;
    memcpy(result, document, before);
    memcpy(result + before, value, replacement);
    memcpy(result + before + replacement, end, after + 1);
    free(document);
    return result;
}

static int safe_receipt_value(const char *value) {
    if (!value || !*value) return 0;
    for (const char *at = value; *at; ++at)
        if (!((*at >= 'A' && *at <= 'Z') || (*at >= 'a' && *at <= 'z') ||
              (*at >= '0' && *at <= '9') || *at == '.' || *at == '_' || *at == '-'))
            return 0;
    return 1;
}

static Obj replacement_legacy_receipt(Obj self, Sel cmd) {
    Obj original = original_legacy_receipt(self, cmd);
    Obj transaction_id = send0(self, "transactionIdentifier");
    Obj payment = send0(self, "payment");
    const char *identifier = utf8(send0(payment, "productIdentifier"));
    const char *bundle = utf8(send0(send0((Obj)objc_getClass("NSBundle"), "mainBundle"),
                                   "bundleIdentifier"));
    const char *number = utf8(transaction_id);
    if (!original || !safe_receipt_value(identifier) || !safe_receipt_value(bundle) ||
        !safe_receipt_value(number)) return original;
    size_t length = (size_t)send0(original, "length");
    if (length < 100 || length > 65536) return original;
    const char *bytes = (const char *)send0(original, "bytes");
    char *outer = malloc(length + 1);
    if (!outer) return original;
    memcpy(outer, bytes, length);
    outer[length] = 0;
    char *encoded_inner = copy_field(outer, "purchase-info");
    size_t inner_length = 0;
    char *inner = encoded_inner ? base64_decode(encoded_inner, &inner_length) : NULL;
    free(encoded_inner);
    if (!inner || !strstr(inner, "com.zeptolab.ctrbonus.superpower1") ||
        !strstr(inner, "com.zeptolab.ctrexperiments")) {
        free(inner);
        free(outer);
        return original;
    }
    char *next = replace_field(inner, "product-id", identifier);
    if (!next) { free(inner); free(outer); return original; }
    inner = next;
    next = replace_field(inner, "bid", bundle);
    if (!next) { free(inner); free(outer); return original; }
    inner = next;
    next = replace_field(inner, "transaction-id", number);
    if (!next) { free(inner); free(outer); return original; }
    inner = next;
    next = replace_field(inner, "original-transaction-id", number);
    if (!next) { free(inner); free(outer); return original; }
    inner = next;
    char *reencoded = base64_encode(inner, strlen(inner));
    free(inner);
    if (!reencoded) { free(outer); return original; }
    next = replace_field(outer, "purchase-info", reencoded);
    free(reencoded);
    if (!next) { free(outer); return original; }
    Obj adjusted = ((Obj (*)(Obj, Sel, const void *, size_t))objc_msgSend)(
        (Obj)objc_getClass("NSData"), selector("dataWithBytes:length:"), next, strlen(next));
    free(next);
    syslog(5, "LocalAPStoreOffline repaired legacy receipt identity for %s", identifier);
    if (adjusted && zombie_mode && zombie_pending_product &&
        ((int (*)(Obj, Sel, Obj))objc_msgSend)(zombie_pending_product,
            selector("isEqualToString:"), send0(payment, "productIdentifier")))
        zombie_receipt_ready = 1;
    return adjusted ? adjusted : original;
}

static unsigned char replacement_zombie_receipt_status(Obj self, Sel cmd, Obj response) {
    load_configuration();
    if (zombie_mode && zombie_receipt_ready && response &&
        ((int (*)(Obj, Sel, Obj))objc_msgSend)(response, selector("isEqualToString:"),
            string("{}"))) {
        /* The game's offline receipt matches the pending product, but its
         * discontinued remote validator supplies no status. Use its parser. */
        syslog(5, "LocalAPStoreOffline supplied offline receipt status for %s",
               utf8(zombie_pending_product));
        return original_zombie_receipt_status(self, cmd, string("{\"status\":0}"));
    }
    return original_zombie_receipt_status(self, cmd, response);
}

static void install_legacy_receipt_hook(void) {
    if (legacy_receipt_hooked || (!configuration && !automatic_products)) return;
    Cls transaction = objc_getClass("SKPaymentTransaction");
    if (!transaction) return;
    MSHookMessageEx(transaction, selector("transactionReceipt"),
                    (void *)replacement_legacy_receipt, (void **)&original_legacy_receipt);
    legacy_receipt_hooked = 1;
}

static void replacement_ski_updated(Obj self, Sel cmd, Obj queue, Obj transactions) {
    load_configuration();
    if (!ski_mode) {
        original_ski_updated(self, cmd, queue, transactions);
        return;
    }
    install_legacy_receipt_hook();
    if (!ski_seen_transactions)
        ski_seen_transactions = send0(send0((Obj)objc_getClass("NSMutableSet"), "alloc"), "init");
    Obj forwarded = send0((Obj)objc_getClass("NSMutableArray"), "array");
    unsigned count = (unsigned)(size_t)send0(transactions, "count");
    for (unsigned i = 0; i < count; ++i) {
        Obj transaction = ((Obj (*)(Obj, Sel, unsigned))objc_msgSend)(
            transactions, selector("objectAtIndex:"), i);
        int purchased = (int)(size_t)send0(transaction, "transactionState") == 1;
        Obj transaction_id = send0(transaction, "transactionIdentifier");
        if (purchased && (!transaction_id ||
                ((int (*)(Obj, Sel, Obj))objc_msgSend)(ski_seen_transactions,
                    selector("containsObject:"), transaction_id))) {
            send1(queue, "finishTransaction:", transaction);
            syslog(5, "LocalAPStoreOffline discarded duplicate Ski Safari transaction");
            continue;
        }
        if (purchased) send1(ski_seen_transactions, "addObject:", transaction_id);
        send1(forwarded, "addObject:", transaction);
    }
    if ((size_t)send0(forwarded, "count"))
        original_ski_updated(self, cmd, queue, forwarded);
}

static void replacement_observer_updated(Obj self, Sel cmd, Obj queue, Obj transactions) {
    UpdatedTransactions original = NULL;
    Cls klass = object_getClass(self);
    for (unsigned i = 0; i < observer_hook_count; ++i)
        if (observer_hooks[i].klass == klass) {
            original = observer_hooks[i].original;
            break;
        }
    if (!original) return;
    Obj bundle = send0(send0((Obj)objc_getClass("NSBundle"), "mainBundle"), "bundleIdentifier");
    /* Pinball's validated path predates this generic filter. */
    if (!strcmp(utf8(bundle), "com.gameprom.software.PinballHD")) {
        original(self, cmd, queue, transactions);
        return;
    }
    if (!seen_transaction_ids) {
        seen_transaction_ids = send0(send0((Obj)objc_getClass("NSMutableSet"), "alloc"), "init");
    }
    Obj forwarded = send0((Obj)objc_getClass("NSMutableArray"), "array");
    unsigned count = (unsigned)(size_t)send0(transactions, "count");
    for (unsigned i = 0; i < count; ++i) {
        Obj transaction = ((Obj (*)(Obj, Sel, unsigned))objc_msgSend)(
            transactions, selector("objectAtIndex:"), i);
        int purchased = (int)(size_t)send0(transaction, "transactionState") == 1;
        Obj transaction_id = send0(transaction, "transactionIdentifier");
        if (purchased && (!transaction_id ||
                ((int (*)(Obj, Sel, Obj))objc_msgSend)(seen_transaction_ids,
                    selector("containsObject:"), transaction_id))) {
            send1(queue, "finishTransaction:", transaction);
            syslog(5, "LocalAPStoreOffline discarded unnumbered or repeated transaction");
            continue;
        }
        if (purchased) send1(seen_transaction_ids, "addObject:", transaction_id);
        if (purchased) {
            Obj payment = send0(transaction, "payment");
            syslog(5, "LocalAPStoreOffline forwarded observer=%p id=%s product=%s",
                   self, utf8(transaction_id), utf8(send0(payment, "productIdentifier")));
        }
        send1(forwarded, "addObject:", transaction);
    }
    if ((size_t)send0(forwarded, "count")) original(self, cmd, queue, forwarded);
}

static void replacement_queue_add_payment(Obj self, Sel cmd, Obj payment) {
    load_configuration();
    if (zombie_mode) {
        if (zombie_pending_product) send0(zombie_pending_product, "release");
        zombie_pending_product = send0(send0(payment, "productIdentifier"), "retain");
        zombie_receipt_ready = 0;
    }
    syslog(5, "LocalAPStoreOffline addPayment product=%s",
           utf8(send0(payment, "productIdentifier")));
    original_queue_add_payment(self, cmd, payment);
}

static void replacement_add_observer(Obj self, Sel cmd, Obj observer) {
    load_configuration();
    if (automatic_products)
        syslog(5, "LocalAPStoreOffline addTransactionObserver instance=%p class=%p",
               observer, observer ? object_getClass(observer) : NULL);
    if (automatic_products && observer && observer_hook_count < 32 &&
        ((int (*)(Obj, Sel, Sel))objc_msgSend)(observer, selector("respondsToSelector:"),
            selector("paymentQueue:updatedTransactions:"))) {
        Cls klass = object_getClass(observer);
        unsigned index = 0;
        for (; index < observer_hook_count; ++index)
            if (observer_hooks[index].klass == klass) break;
        if (index == observer_hook_count) {
            observer_hooks[index].klass = klass;
            MSHookMessageEx(klass, selector("paymentQueue:updatedTransactions:"),
                            (void *)replacement_observer_updated,
                            (void **)&observer_hooks[index].original);
            ++observer_hook_count;
            syslog(5, "LocalAPStoreOffline guarded StoreKit observer %p", klass);
        }
    }
    original_add_observer(self, cmd, observer);
}

static Cls register_subclass(const char *parent, const char *name) {
    Cls superclass = objc_getClass(parent);
    /* A missing StoreKit class must not produce an NSObject-less root class. */
    if (!superclass) return NULL;
    Cls klass = objc_allocateClassPair(superclass, name, 0);
    if (klass) objc_registerClassPair(klass);
    return klass ? klass : objc_getClass(name);
}

__attribute__((constructor)) static void install(void) {
    if (access("/Library/MobileSubstrate/DynamicLibraries/LocalIAPStore.dylib", 0)) return;
    product_class = register_subclass("SKProduct", "LocalAPStoreOfflineProduct");
    response_class = register_subclass("SKProductsResponse", "LocalAPStoreOfflineResponse");
    Cls request_class = objc_getClass("SKProductsRequest");
    if (!product_class || !response_class || !request_class) return;
    class_addMethod(product_class, selector("productIdentifier"), (void *)product_identifier, "@@:");
    class_addMethod(product_class, selector("localizedTitle"), (void *)product_title, "@@:");
    class_addMethod(product_class, selector("localizedDescription"), (void *)product_title, "@@:");
    class_addMethod(product_class, selector("price"), (void *)product_price, "@@:");
    class_addMethod(product_class, selector("priceLocale"), (void *)product_locale, "@@:");
    class_addMethod(product_class, selector("isDownloadable"), (void *)product_not_downloadable, "c@:");
    class_addMethod(response_class, selector("products"), (void *)response_products, "@@:");
    class_addMethod(response_class, selector("invalidProductIdentifiers"), (void *)response_invalid, "@@:");
    class_addMethod(request_class, selector("lap_deliverOffline:"), (void *)deliver, "v@:@");
    MSHookMessageEx(request_class, selector("initWithProductIdentifiers:"),
                    (void *)replacement_init, (void **)&original_init);
    MSHookMessageEx(request_class, selector("start"), (void *)replacement_start,
                    (void **)&original_start);
    Cls queue_class = objc_getClass("SKPaymentQueue");
    if (queue_class)
        MSHookMessageEx(queue_class, selector("addTransactionObserver:"),
                        (void *)replacement_add_observer, (void **)&original_add_observer);
    if (queue_class)
        MSHookMessageEx(queue_class, selector("addPayment:"),
                        (void *)replacement_queue_add_payment,
                        (void **)&original_queue_add_payment);
    /* Pinball HD overrides -start; other games can use the inherited hook. */
    Cls game_class = objc_getClass("GBSKProductsRequest");
    if (game_class)
        MSHookMessageEx(game_class, selector("start"), (void *)replacement_game_start,
                        (void **)&original_game_start);
    Cls verifier_class = objc_getClass("VerificationController");
    if (verifier_class)
        MSHookMessageEx(verifier_class, selector("verifyPurchase:completionHandler:"),
                        (void *)replacement_verify_purchase, (void **)&original_verify_purchase);
    Cls jetpack_store = objc_getClass("OFStoreKit");
    if (jetpack_store) {
        MSHookMessageEx((Cls)objc_getClass("SKPaymentQueue"), selector("addPayment:"),
                        (void *)replacement_jetpack_add_payment,
                        (void **)&original_jetpack_add_payment);
        MSHookMessageEx(jetpack_store, selector("paymentQueue:updatedTransactions:"),
                        (void *)replacement_jetpack_updated,
                        (void **)&original_jetpack_updated);
    }
    Cls ski_store = objc_getClass("StoreKitManager");
    if (ski_store)
        MSHookMessageEx(ski_store, selector("paymentQueue:updatedTransactions:"),
                        (void *)replacement_ski_updated, (void **)&original_ski_updated);
    Cls zombie_verifier = objc_getClass("PurchaseVerifier");
    if (zombie_verifier)
        MSHookMessageEx(zombie_verifier,
                        selector("doesTransactionInfoMatchReceipt_PREVENT_HACK_POUF_POUF:"),
                        (void *)replacement_zombie_receipt_status,
                        (void **)&original_zombie_receipt_status);
    syslog(5, "LocalAPStoreOffline hooks installed");
}
