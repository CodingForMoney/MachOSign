//
//  MachOSignature.m
//  MachOSignDemo
//
//  Created by 罗贤明 on 2017/9/1.
//  Copyright © 2017年 罗贤明. All rights reserved.
//

#import "MachOSignature.h"
#include <AssertMacros.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonCrypto.h>
//#import "CCDegist.h"

/*
 * Magic numbers used by Code Signing
 */
enum {
    CSMAGIC_REQUIREMENT	= 0xfade0c00,		/* single Requirement blob */
    CSMAGIC_REQUIREMENTS = 0xfade0c01,		/* Requirements vector (internal requirements) */
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,		/* CodeDirectory blob */
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */
    
    CSSLOT_CODEDIRECTORY = 0,				/* slot index for CodeDirectory */
};


/*
 * Structure of an embedded-signature SuperBlob
 */
typedef struct __BlobIndex {
    uint32_t type;					/* type of entry */
    uint32_t offset;				/* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;					/* magic number */
    uint32_t length;				/* total length of SuperBlob */
    uint32_t count;					/* number of index entries following */
    CS_BlobIndex index[];			/* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;


/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
    uint32_t magic;					/* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;				/* total length of CodeDirectory blob */
    uint32_t version;				/* compatibility version */
    uint32_t flags;					/* setup and mode flags */
    uint32_t hashOffset;			/* offset of hash slot element at index zero */
    uint32_t identOffset;			/* offset of identifier string */
    uint32_t nSpecialSlots;			/* number of special hash slots */
    uint32_t nCodeSlots;			/* number of ordinary (code) hash slots */
    uint32_t codeLimit;				/* limit to main image signature range */
    uint8_t hashSize;				/* size of each hash in bytes */
    uint8_t hashType;				/* type of hash (cdHashType* constants) */
    uint8_t spare1;					/* unused (must be zero) */
    uint8_t	pageSize;				/* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;				/* unused (must be zero) */
    /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;


//assert(page < ntohl(cd->nCodeSlots));
//return base + ntohl(cd->hashOffset) + page * 20;

#if 0
static void debug_data(uint8_t *data, size_t length)
{
    uint32_t i, j;
    for (i = 0; i < length; i+=16) {
        fprintf(stderr, "%p   ", (void*)(data+i));
        for (j = 0; (j < 16) && (j+i < length); j++) {
            uint8_t byte = *(uint8_t*)(data+i+j);
            fprintf(stderr, "%.02x %c|", byte, isprint(byte) ? byte : '?');
        }
        fprintf(stderr, "\n");
    }
}

static void write_data(const char *path, uint8_t *data, size_t length)
{
    int fd = open(path, O_RDWR|O_TRUNC|O_CREAT, 0644);
    require(fd>0, out);
    write(fd, data, length);
    close(fd);
    out:
    return;
}
#endif

static void CFReleaseSafe(CFTypeRef cf) {
    if (cf) {
        CFRelease(cf);
    }
}

static CFMutableDictionaryRef lc_code_sig(uint8_t *lc_code_signature, size_t lc_code_signature_len)
{
    CFMutableDictionaryRef code_signature =
    CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
    require(code_signature, out);
    
    CS_SuperBlob *sb = (CS_SuperBlob*)lc_code_signature;
    require(ntohl(sb->magic) == CSMAGIC_EMBEDDED_SIGNATURE, out);
    uint32_t count;
    for (count = 0; count < ntohl(sb->count); count++) {
        //uint32_t type = ntohl(sb->index[count].type);
        uint32_t offset = ntohl(sb->index[count].offset);
        uint8_t *bytes = lc_code_signature + offset;
        //fprintf(stderr, "blob[%d]: (type: 0x%.08x, offset: %p)\n", count, type, (void*)offset);
        uint32_t magic = ntohl(*(uint32_t*)bytes);
        uint32_t length = ntohl(*(uint32_t*)(bytes+4));
        //fprintf(stderr, "    magic: 0x%.08x length: %d\n", magic, length);
        switch(magic) {
            case 0xfade7171:
            {
                // 真机上有，模拟器上没有。
                unsigned char digest[CC_SHA1_DIGEST_LENGTH];
                //                CCDigest(kCCDigestSHA1, bytes, length, digest);
                CC_SHA1(bytes + 8, length - 8, digest);
                
                CFDataRef message = CFDataCreate(kCFAllocatorDefault, digest, sizeof(digest));
                require(message, out);
                CFDictionarySetValue(code_signature, CFSTR("EntitlementsHash"), message);
                CFRelease(message);
                message = CFDataCreate(kCFAllocatorDefault, bytes+8, length-8);
                require(message, out);
                CFDictionarySetValue(code_signature, CFSTR("Entitlements"), message);
                CFRelease(message);
                break;
                break;
            }
            default:
//                fprintf(stderr, "Skipping block with magic: 0x%x\n", magic);
                break;
        }
    }
    return code_signature;
    out:
    if (code_signature) CFRelease(code_signature);
    return NULL;
}


static FILE *
open_bundle(const char * path, const char * mode)
{
    char full_path[1024] = {};
    CFStringRef path_cfstring = NULL;
    CFURLRef path_url = NULL;
    CFBundleRef bundle = NULL;
    CFURLRef exec = NULL;
    
    path_cfstring = CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault, path);
    require_quiet(path_cfstring, out);
    path_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path_cfstring, kCFURLPOSIXPathStyle, true);
    require_quiet(path_url, out);
    bundle =  CFBundleCreate(kCFAllocatorDefault, path_url);
    require_quiet(bundle, out);
    exec = CFBundleCopyExecutableURL(bundle);
    require(exec, out);
    require(CFURLGetFileSystemRepresentation(exec, true, (uint8_t*)full_path, sizeof(full_path)), out);
    out:
    CFReleaseSafe(path_cfstring);
    CFReleaseSafe(path_url);
    CFReleaseSafe(bundle);
    CFReleaseSafe(exec);
    
    return fopen(full_path, "r");
}

static CFMutableDictionaryRef load_code_signature(FILE *binary, size_t slice_offset)
{
    bool signature_found = false;
    CFMutableDictionaryRef result = NULL;
    struct load_command lc;
    do {
        require(1 == fread(&lc, sizeof(lc), 1, binary), out);
        if (lc.cmd == LC_CODE_SIGNATURE) {
            struct { uint32_t offset; uint32_t size; } sig;
            require(1 == fread(&sig, sizeof(sig), 1, binary), out);
            require_noerr(fseek(binary, slice_offset+sig.offset, SEEK_SET), out);
            size_t length = sig.size;
            uint8_t *data = malloc(length);
            require(length && data, out);
            require(1 == fread(data, length, 1, binary), out);
            signature_found = true;
            result = lc_code_sig(data, length);
            free(data);
            break;
        }
        require_noerr(fseek(binary, lc.cmdsize-sizeof(lc), SEEK_CUR), out);
    } while(lc.cmd || lc.cmdsize); /* count lc */
    out:
    if (!signature_found)
        fprintf(stderr, "No LC_CODE_SIGNATURE segment found\n");
    return result;
}


static CF_RETURNS_RETAINED CFArrayRef load_code_signatures(const char *path)
{
    bool fully_parsed_binary = false;
    CFMutableDictionaryRef result = NULL;
    CFMutableArrayRef results = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    
    FILE *binary = open_bundle(path, "r");
    if (!binary) binary = fopen(path, "r");
    require(binary, out);
    
    struct mach_header header;
    require(1 == fread(&header, sizeof(header), 1, binary), out);
    if ((header.magic == MH_MAGIC) || (header.magic == MH_MAGIC_64)) {
        if (header.magic == MH_MAGIC_64)
            fseek(binary, sizeof(struct mach_header_64) - sizeof(struct mach_header), SEEK_CUR);
        result = load_code_signature(binary, 0 /*non fat*/);
        require(result, out);
        CFStringRef type = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("CPU type: (%d,%d)"), header.cputype, header.cpusubtype);
        CFDictionarySetValue(result, CFSTR("ARCH"), type);
        CFRelease(type);
        CFArrayAppendValue(results, result);
    }
    else
    {
        struct fat_header fat;
        require(!fseek(binary, 0L, SEEK_SET), out);
        require(1 == fread(&fat, sizeof(fat), 1, binary), out);
        require(ntohl(fat.magic) == FAT_MAGIC, out);
        uint32_t slice, slices = ntohl(fat.nfat_arch);
        struct fat_arch *archs = calloc(slices, sizeof(struct fat_arch));
        require(slices == fread(archs, sizeof(struct fat_arch), slices, binary), out);
        for (slice = 0; slice < slices; slice++) {
            uint32_t slice_offset = ntohl(archs[slice].offset);
            require(!fseek(binary, slice_offset, SEEK_SET), out);
            require(1 == fread(&header, sizeof(header), 1, binary), out);
            require((header.magic == MH_MAGIC) || (header.magic == MH_MAGIC_64), out);
            if (header.magic == MH_MAGIC_64)
                fseek(binary, sizeof(struct mach_header_64) - sizeof(struct mach_header), SEEK_CUR);
            result = load_code_signature(binary, slice_offset);
            require(result, out);
            CFStringRef type = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("CPU type: (%d,%d)"), header.cputype, header.cpusubtype);
            CFDictionarySetValue(result, CFSTR("ARCH"), type);
            CFRelease(type);
            CFArrayAppendValue(results, result);
            CFRelease(result);
        }
    }
    fully_parsed_binary = true;
    out:
    if (!fully_parsed_binary) {
        if (results) {
            CFRelease(results);
            results = NULL;
        }
    }
    if (binary)
        fclose(binary);
    return results;
}


@implementation MachOSignature

+ (NSDictionary *)loadSignature {
    CFArrayRef array = load_code_signatures([NSBundle mainBundle].executablePath.UTF8String);
    NSDictionary *ret;
    if (array) {
        if (CFArrayGetCount(array)) {
            NSArray *list = (__bridge_transfer NSArray *)array;
            NSDictionary *dic = list[0];
            NSData *EntitlementsData = dic[@"Entitlements"];
            NSData *EntitlementsHashData = dic[@"EntitlementsHash"];
            if (EntitlementsData && EntitlementsHashData) {
                ret = [[NSMutableDictionary alloc] init];
                NSString *Entitlements = [[NSString alloc] initWithData:EntitlementsData
                                                               encoding:NSUTF8StringEncoding];
                [ret setValue:Entitlements forKey:@"Entitlements"];
                NSMutableString *string = [@"" mutableCopy];
                [EntitlementsHashData enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
                    unsigned char *dataBytes = (unsigned char*)bytes;
                    for (NSInteger i = 0; i < byteRange.length; i++) {
                        NSString *hexStr = [NSString stringWithFormat:@"%x", (dataBytes[i]) & 0xff];
                        if ([hexStr length] == 2) {
                            [string appendString:hexStr];
                        } else {
                            [string appendFormat:@"0%@", hexStr];
                        }
                    }
                }];
                [ret setValue:string forKey:@"EntitlementsHash"];
            }
        }else {
            CFRelease(array);
        }
    }
    return ret;
}


@end
