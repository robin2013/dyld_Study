/* -*- mode: C++; c-basic-offset: 4; tab-width: 4 -*-
 *
 * Copyright (c) 2004-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <Availability.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/ldsyms.h>
#include <mach-o/reloc.h>
#if __x86_64__
	#include <mach-o/x86_64/reloc.h>
#endif
#include "dyld.h"
#include "dyldSyscallInterface.h"

// from dyld_gdb.cpp 
extern void addImagesToAllImages(uint32_t infoCount, const dyld_image_info info[]);
extern void syncProcessInfo();

#ifndef MH_PIE
	#define MH_PIE 0x200000 
#endif

// currently dyld has no initializers, but if some come back, set this to non-zero
#define DYLD_INITIALIZER_SUPPORT  0

#if __LP64__
	#define LC_SEGMENT_COMMAND		LC_SEGMENT_64
	#define macho_segment_command	segment_command_64
	#define macho_section			section_64
	#define RELOC_SIZE				3
#else
	#define LC_SEGMENT_COMMAND		LC_SEGMENT
	#define macho_segment_command	segment_command
	#define macho_section			section
	#define RELOC_SIZE				2
#endif

#if __x86_64__
	#define POINTER_RELOC X86_64_RELOC_UNSIGNED
#else
	#define POINTER_RELOC GENERIC_RELOC_VANILLA
#endif


#if TARGET_IPHONE_SIMULATOR
const dyld::SyscallHelpers* gSyscallHelpers = NULL;
#endif


//
//  Code to bootstrap dyld into a runnable state
//
//

namespace dyldbootstrap {



#if DYLD_INITIALIZER_SUPPORT

typedef void (*Initializer)(int argc, const char* argv[], const char* envp[], const char* apple[]);

//Section64(__Data_CONST,__mof_init_func) 节的开始地址
extern const Initializer  inits_start  __asm("section$start$__DATA$__mod_init_func");
//Section64(__Data_CONST,__mof_init_func) 节的结束地址
extern const Initializer  inits_end    __asm("section$end$__DATA$__mod_init_func");

//
// For a regular executable, the crt code calls dyld to run the executables initializers.
// For a static executable, crt directly runs the initializers.
// dyld (should be static) but is a dynamic executable and needs this hack to run its own initializers.
// We pass argc, argv, etc in case libc.a uses those arguments
//
static void runDyldInitializers(const struct macho_header* mh, intptr_t slide, int argc, const char* argv[], const char* envp[], const char* apple[])
{
    // 遍历Section64(__Data_CONST,__mof_init_func) 节中的所有函数地址, 依次调用 C++ 的初始化函数，也就是调用被 __attribute__((constructor)) 修饰的函数

	for (const Initializer* p = &inits_start; p < &inits_end; ++p) {
		(*p)(argc, argv, envp, apple);
	}
}
#endif // DYLD_INITIALIZER_SUPPORT


//
//  The kernel may have slid a Position Independent Executable
//
// 获取主app的滑动地址长度
static uintptr_t slideOfMainExecutable(const struct macho_header* mh)
{
    // load command数量
	const uint32_t cmd_count = mh->ncmds;
    // 全部cmd的索引
	const struct load_command* const cmds = (struct load_command*)(((char*)mh)+sizeof(macho_header));
    // 第一个cmd 地址
	const struct load_command* cmd = cmds;
	for (uint32_t i = 0; i < cmd_count; ++i) {
		if ( cmd->cmd == LC_SEGMENT_COMMAND ) { // 如果是段命令
			const struct macho_segment_command* segCmd = (struct macho_segment_command*)cmd;
			if ( (segCmd->fileoff == 0) && (segCmd->filesize != 0)) {// fileoffset == 0 且 filesize != 只有LC_SEGMENT_64(__TEXT)
                // 返回当前mh地址与LC_SEGMENT_64(__TEXT)在虚拟内存中的地址之差, 即为slide
				return (uintptr_t)mh - segCmd->vmaddr;
			}
		}
		cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
	}
	return 0;
}


//
// If the kernel does not load dyld at its preferred address, we need to apply 
// fixups to various initialized parts of the __DATA segment
//

/// dyld 重定位
/// @param mh dyld macho header地址
/// @param slide 滑动内存长度
static void rebaseDyld(const struct macho_header* mh, intptr_t slide)
{
	// rebase non-lazy pointers (which all point internal to dyld, since dyld uses no shared libraries)
	// and get interesting pointers into dyld
    // 获取load command数量
	const uint32_t cmd_count = mh->ncmds;
    // 将macho的首地址按照 macho_header 长度偏移 ,得到load command地址
	const struct load_command* const cmds = (struct load_command*)(((char*)mh)+sizeof(macho_header));
    // 第一个cmd
	const struct load_command* cmd = cmds;
	const struct macho_segment_command* linkEditSeg = NULL;
#if __x86_64__
	const struct macho_segment_command* firstWritableSeg = NULL;
#endif
	const struct dysymtab_command* dynamicSymbolTable = NULL;
	for (uint32_t i = 0; i < cmd_count; ++i) {
		switch (cmd->cmd) {
                // 段命令
			case LC_SEGMENT_COMMAND:
				{
					const struct macho_segment_command* seg = (struct macho_segment_command*)cmd;
					if ( strcmp(seg->segname, "__LINKEDIT") == 0 )// 如果是 __LINKEDIT
						linkEditSeg = seg;
                    /*
                     __LINKEDIT __PAGEZERO 这两个seg的section header数量为0
                     这里主要是遍历__TEXT, __DATA的section header
                     */
                    //从__TEXT 或 __DATA 的seg地址按照 macho_segment_command 长度偏移, 得到一个 section header的地址
					const struct macho_section* const sectionsStart = (struct macho_section*)((char*)seg + sizeof(struct macho_segment_command));
                    // 设置 section header 结尾
					const struct macho_section* const sectionsEnd = &sectionsStart[seg->nsects];
                    // 遍历 section header
					for (const struct macho_section* sect=sectionsStart; sect < sectionsEnd; ++sect) {
                        // section header 类型
						const uint8_t type = sect->flags & SECTION_TYPE;
                        // section header 类型是非懒加载指针类型
						if ( type == S_NON_LAZY_SYMBOL_POINTERS ) {
							// rebase non-lazy pointers (which all point internal to dyld, since dyld uses no shared libraries)
                            // 获取指针数量(sect->size 为 section header 对应section 的长度)
							const uint32_t pointerCount = (uint32_t)(sect->size / sizeof(uintptr_t));
                            // 通过 section header 标记的dyld在虚拟内存中的地址, 加上滑动空间,得到首个section 对应的8字节内容
							uintptr_t* const symbolPointers = (uintptr_t*)(sect->addr + slide);
							for (uint32_t j=0; j < pointerCount; ++j) {
                                // 将每个8字节指针地址偏移slide个位置
								symbolPointers[j] += slide;
							}
						}
					}
#if __x86_64__
					if ( (firstWritableSeg == NULL) && (seg->initprot & VM_PROT_WRITE) )
						firstWritableSeg = seg;
#endif
				}
				break;
			case LC_DYSYMTAB:// 动态符号表命令
				dynamicSymbolTable = (struct dysymtab_command *)cmd;
				break;
		}
        // 下一个command
		cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
	}
	
	// use reloc's to rebase all random data pointers
#if __x86_64__
	const uintptr_t relocBase = firstWritableSeg->vmaddr + slide;
#else
    // recloc  重定位的基地址
	const uintptr_t relocBase = (uintptr_t)mh;
#endif
    // 定位需要重定位数据的内存地址
    // __LINKEDIT，其中包含需要被动态链接器使用的信息，包括符号表、字符串表、重定位项表、签名等

    //linkEditSeg->vmaddr + slide 定位到重定位数据的首地址(Dynamic Loader Info)
    // dynamicSymbolTable->locreloff: table索引偏移(offset to local relocation entries: table中按照entity存着重定位对象)
    //linkEditSeg的fileoff +filesize即为MachO文件末尾，也就是等于文件的大小

    /*
     - linkEditSeg->fileoff: 基于linkEditSeg的addr 减去fileoff, 因为以下原因
     原始地址(文件地址): begin + fileoff，大小为filesize
     目的地址(进程虚址): vmaddr，大小为vmsize
     其中vmsize >= filesize，如果有多出来的部分需要(前方)填充为零。

      MachO文件地址 = Linkedit虚拟地址 - 当前段在文件中的偏移量 + ASLR(slide)

     https://blog.csdn.net/u010206565/article/details/108432252
     https://www.coderzhou.com
     https://www.bbsmax.com/A/q4zVYLL2dK/
     找出 LC_DYSYMTAB 和 __LINKEDIT 对应的 command；
     对非懒加载表进行 rebase；
     取出 relocation 对应位置的指针，加上 slide，进行 rebase；
     https://juejin.cn/post/6974678419715932174#heading-20
     */
	const relocation_info* const relocsStart = (struct relocation_info*)(linkEditSeg->vmaddr + slide + dynamicSymbolTable->locreloff - linkEditSeg->fileoff);
	const relocation_info* const relocsEnd = &relocsStart[dynamicSymbolTable->nlocrel];
	for (const relocation_info* reloc=relocsStart; reloc < relocsEnd; ++reloc) {
		if ( reloc->r_length != RELOC_SIZE ) 
			throw "relocation in dyld has wrong size";

		if ( reloc->r_type != POINTER_RELOC ) 
			throw "relocation in dyld has wrong type";
		
		// update pointer by amount dyld slid
		*((uintptr_t*)(reloc->r_address + relocBase)) += slide;
	}
}


extern "C" void mach_init();
extern "C" void __guard_setup(const char* apple[]);


//
//  This is code to bootstrap dyld.  This work in normally done for a program by dyld and crt.
//  In dyld we have to do this manually.
//

/// dyld 启动函数
/// @param appsMachHeader 主App macho 头地址
/// @param argc 参数数量
/// @param argv 参数
/// @param slide 滑动地址
/// @param dyldsMachHeader dyld macho 头地址
/// @param startGlue
uintptr_t start(const struct macho_header* appsMachHeader, int argc, const char* argv[], 
				intptr_t slide, const struct macho_header* dyldsMachHeader,
				uintptr_t* startGlue)
{
	// if kernel had to slide dyld, we need to fix up load sensitive locations
	// we have to do this before using any global variables
	if ( slide != 0 ) {
        // dyld 内存地址重定位
		rebaseDyld(dyldsMachHeader, slide);
	}

	// allow dyld to use mach messaging
	mach_init();

	// kernel sets up env pointer to be just past end of agv array
	const char** envp = &argv[argc+1];
	
	// kernel sets up apple pointer to be just past end of envp array
	const char** apple = envp;
	while(*apple != NULL) { ++apple; }
	++apple;

	// set up random value for stack canary
    // 栈溢出保护
	__guard_setup(apple);

#if DYLD_INITIALIZER_SUPPORT
	// run all C++ initializers inside dyld
    // 这里就是调用 C++ 的初始化函数，也就是调用被 __attribute__((constructor)) 修饰的函数
	runDyldInitializers(dyldsMachHeader, slide, argc, argv, envp, apple);
#endif

	// now that we are done bootstrapping dyld, call dyld's main
    // 前mh地址与LC_SEGMENT_64(__TEXT)在虚拟内存中的地址之差, 即为slide
	uintptr_t appsSlide = slideOfMainExecutable(appsMachHeader);
    // 进入dyld::_main()函数
	return dyld::_main(appsMachHeader, appsSlide, argc, argv, envp, apple, startGlue);
}


#if TARGET_IPHONE_SIMULATOR

extern "C" uintptr_t start_sim(int argc, const char* argv[], const char* envp[], const char* apple[],
							const macho_header* mainExecutableMH, const macho_header* dyldMH, uintptr_t dyldSlide,
							const dyld::SyscallHelpers*, uintptr_t* startGlue);
					
					
uintptr_t start_sim(int argc, const char* argv[], const char* envp[], const char* apple[],
					const macho_header* mainExecutableMH, const macho_header* dyldMH, uintptr_t dyldSlide,
					const dyld::SyscallHelpers* sc, uintptr_t* startGlue)
{
	// if simulator dyld loaded slid, it needs to rebase itself
	// we have to do this before using any global variables
	if ( dyldSlide != 0 ) {
		rebaseDyld(dyldMH, dyldSlide);
	}

	// save table of syscall pointers
	gSyscallHelpers = sc;
	
	// allow dyld to use mach messaging
    // mach消息初始化
	mach_init();

	// set up random value for stack canary
    // 栈溢出保护
	__guard_setup(apple);

	// setup gProcessInfo to point to host dyld's struct
	dyld::gProcessInfo = (struct dyld_all_image_infos*)(sc->getProcessInfo());
	syncProcessInfo();

	// now that we are done bootstrapping dyld, call dyld's main
	uintptr_t appsSlide = slideOfMainExecutable(mainExecutableMH);
    // 进入dyld::_main()函数
	return dyld::_main(mainExecutableMH, appsSlide, argc, argv, envp, apple, startGlue);
}
#endif


} // end of namespace




