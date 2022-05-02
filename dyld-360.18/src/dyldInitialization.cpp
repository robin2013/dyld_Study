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

extern const Initializer  inits_start  __asm("section$start$__DATA$__mod_init_func");
extern const Initializer  inits_end    __asm("section$end$__DATA$__mod_init_func");

//
// For a regular executable, the crt code calls dyld to run the executables initializers.
// For a static executable, crt directly runs the initializers.
// dyld (should be static) but is a dynamic executable and needs this hack to run its own initializers.
// We pass argc, argv, etc in case libc.a uses those arguments
//
/*
 inits_start 和 inits_end 采用内敛汇编的方式获取模块初始化函数的地址
 所谓模块初始化函数 就是在加载模块时就要完成的初始化动作(可能在main函数之前), 比如模块使用的包含初始化函数的全局变量, c++类的初始化等等
 
 参见 https://blog.csdn.net/majiakun1/article/details/99413403
 */

static void runDyldInitializers(const struct macho_header* mh, intptr_t slide, int argc, const char* argv[], const char* envp[], const char* apple[])
{
	for (const Initializer* p = &inits_start; p < &inits_end; ++p) {
		(*p)(argc, argv, envp, apple);
	}
}
#endif // DYLD_INITIALIZER_SUPPORT


//
//  The kernel may have slid a Position Independent Executable
//
static uintptr_t slideOfMainExecutable(const struct macho_header* mh)
{
	// LC Command的数量
	const uint32_t cmd_count = mh->ncmds;
	// 拿到第所有cmd的首地址
	const struct load_command* const cmds = (struct load_command*)(((char*)mh)+sizeof(macho_header));
	// 强转类型, 拿到第一个cmd地址
	const struct load_command* cmd = cmds;
	// 遍历cmd
	for (uint32_t i = 0; i < cmd_count; ++i) {
		// 如果是段命令
		if ( cmd->cmd == LC_SEGMENT_COMMAND ) {
			const struct macho_segment_command* segCmd = (struct macho_segment_command*)cmd;
			// 如果是代码段cmd
			if ( strcmp(segCmd->segname, "__TEXT") == 0 ) {
				// 返回 mach首地址和代码段在虚拟内存地址的差值(在mach文件中, 代码段定义的虚拟内存的地址和mach文件首地址是一样的, mh偏移后, 减去代码段文件中定义的虚拟内存首地址, 即可获得滑动地址)
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
// 根据滑动地址空间, rebaseapp虚拟内存地址
static void rebaseDyld(const struct macho_header* mh, intptr_t slide)
{
	// rebase non-lazy pointers (which all point internal to dyld, since dyld uses no shared libraries)
	// and get interesting pointers into dyld
	// 获取 load command 的数量(数量保存在mach header的信息中)
	const uint32_t cmd_count = mh->ncmds;
	// 将mh内存按照macho_header的长度进行偏移, 此时cmds指向load commands的起始位置(macho的起始位置是macho_header)
	const struct load_command* const cmds = (struct load_command*)(((char*)mh)+sizeof(macho_header));
	
	//load commands的起始位置 , 也就是第一个load command的位置, 即__PAGEZERO
	const struct load_command* cmd = cmds;
	//LC_SEGMENT_64(__LINKEDIT)
	// https://www.coderzhou.com
	const struct macho_segment_command* linkEditSeg = NULL;
#if __x86_64__
	const struct macho_segment_command* firstWritableSeg = NULL;
#endif
	//LC_DYSYMTAB 动态符号表
	const struct dysymtab_command* dynamicSymbolTable = NULL;
	// 遍历全部加载命令
	for (uint32_t i = 0; i < cmd_count; ++i) {
		// 匹配命令类型
		switch (cmd->cmd) {
				// 如果是64位加载命令(LC_SEGMENT_64(__PAGEZERO, __TEXT, __DATA, __LINKEDIT))
			case LC_SEGMENT_COMMAND:
				{
					// 获取当前加载命令下的第一个段(SEGMENT, cmd的首地址即为第一个段的地址)
					const struct macho_segment_command* seg = (struct macho_segment_command*)cmd;
					//__LINKEDIT段包含动态链接器使用的原始数据，例如符号，字符串和重定位表条目
					if ( strcmp(seg->segname, "__LINKEDIT") == 0 )
						linkEditSeg = seg;
					// 将段的首地址按段命令(macho_segment_command)的长度偏移, 得到第一个 section header 地址
					const struct macho_section* const sectionsStart = (struct macho_section*)((char*)seg + sizeof(struct macho_segment_command));
					// 从 section header 的首地址,偏移到最后一个 section header 的结尾, 得到 section header 结束的位置
					const struct macho_section* const sectionsEnd = &sectionsStart[seg->nsects];
					// 遍历当前segement下的所有 section header
					for (const struct macho_section* sect=sectionsStart; sect < sectionsEnd; ++sect) {
						const uint8_t type = sect->flags & SECTION_TYPE;
						// 如果 section header 的类型是直接加载指针类型(非懒加载, 其对应的 Section 存的都是数据指针,如(Section64(__DATA,__got)))
						if ( type == S_NON_LAZY_SYMBOL_POINTERS ) {
							// rebase non-lazy pointers (which all point internal to dyld, since dyld uses no shared libraries)
							// 按照 section header 记录的 Section 的长度, 除以指针长度, 得到对应 Section 内的指针数量
							const uint32_t pointerCount = (uint32_t)(sect->size / sizeof(uintptr_t));
							// 将 section header 中记录的 Section 首地址偏移 slide 个单位, 得到其对应的 Section 起始地址
							// (参见SectionHeader(__got) --> Section64(__DATA,__got)))
							uintptr_t* const symbolPointers = (uintptr_t*)(sect->addr + slide);
							// 遍历节内的所有指针
							for (uint32_t j=0; j < pointerCount; ++j) {
								// 对每个指针偏移 slide 单位的长度
								symbolPointers[j] += slide;
							}
						}
					}
#if __x86_64__
					// 判断是否为第一个可写入的段 (VM_PROT_WRITE, 写入权限)
					if ( (firstWritableSeg == NULL) && (seg->initprot & VM_PROT_WRITE) )
						firstWritableSeg = seg;
#endif
				}
				break;
				// 如果是动态符号表命令, 直接赋值
			case LC_DYSYMTAB:
				dynamicSymbolTable = (struct dysymtab_command *)cmd;
				break;
		}
		// cmd指针偏移到下一个 load command 位置
		cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
	}
	
	// use reloc's to rebase all random data pointers
#if __x86_64__
	const uintptr_t relocBase = firstWritableSeg->vmaddr + slide;
#else
	// macho内存数据的首地址
	const uintptr_t relocBase = (uintptr_t)mh;
#endif
	// 定位需要重定位数据的内存地址
	//linkEditSeg->vmaddr + slide 定位到重定位数据的首地址(Dynamic Loader Info)
	// dynamicSymbolTable->locreloff: table索引偏移(offset to local relocation entries: table中按照entity存着重定位对象)

	/*
	 - linkEditSeg->fileoff: 基于linkEditSeg的addr 减去fileoff, 因为以下原因
	 原始地址(文件地址): begin + fileoff，大小为filesize
	 目的地址(进程虚址): vmaddr，大小为vmsize
	 其中vmsize >= filesize，如果有多出来的部分需要填充为零。

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
	// 获取最后一个重定位对象的最后一个地址
	const relocation_info* const relocsEnd = &relocsStart[dynamicSymbolTable->nlocrel];
	for (const relocation_info* reloc=relocsStart; reloc < relocsEnd; ++reloc) {
		if ( reloc->r_length != RELOC_SIZE ) 
			throw "relocation in dyld has wrong size";

		if ( reloc->r_type != POINTER_RELOC ) 
			throw "relocation in dyld has wrong type";
		
		// update pointer by amount dyld slid
		// 修改每一个重定位对象的地址
		*((uintptr_t*)(reloc->r_address + relocBase)) += slide;
	}
}


extern "C" void mach_init();
extern "C" void __guard_setup(const char* apple[]);


//
//  This is code to bootstrap dyld.  This work in normally done for a program by dyld and crt.
//  In dyld we have to do this manually.
//
uintptr_t start(const struct macho_header* appsMachHeader, int argc, const char* argv[], 
				intptr_t slide, const struct macho_header* dyldsMachHeader,
				uintptr_t* startGlue)
{
	// if kernel had to slide dyld, we need to fix up load sensitive locations
	// we have to do this before using any global variables
	if ( slide != 0 ) {// 内存滑动不为空
		// 滑动虚拟内存地址
		/*
		 ：这个方法的rebaseDyld是dyld完成自身重定位的方法。首先dyld本身也是一个动态库。对于普通动态库，符号重定位可以由dyld来加载链接来完成，但是dyld的重定位谁来做？只能是它自身完成。这就是为什么会有rebaseDyld的原因，它其实是在对自身进行重定位，只有完成了自身的重定位它才能使用全局变量和静态变量。

		 作者：普度拉稀
		 链接：https://www.jianshu.com/p/48554edb8e28
		 来源：简书
		 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
		 */
		rebaseDyld(dyldsMachHeader, slide);
	}

	// allow dyld to use mach messaging
	// 获取mach消息权限
	mach_init();

	// kernel sets up env pointer to be just past end of agv array
	//  获取环境变量
	const char** envp = &argv[argc+1];
	
	// kernel sets up apple pointer to be just past end of envp array
	const char** apple = envp;
	while(*apple != NULL) { ++apple; }
	++apple;

	// set up random value for stack canary
	// 栈保护
	__guard_setup(apple);

#if DYLD_INITIALIZER_SUPPORT
	// run all C++ initializers inside dyld
	/*
	 调用dyld的初始化模块
	 inits_start 和 inits_end 采用内敛汇编的方式获取模块初始化函数的地址
	 所谓模块初始化函数 就是在加载模块时就要完成的初始化动作(可能在main函数之前), 比如模块使用的包含初始化函数的全局变量, c++类的初始化等等
	 */
	runDyldInitializers(dyldsMachHeader, slide, argc, argv, envp, apple);
#endif

	// now that we are done bootstrapping dyld, call dyld's main
	//获得app在虚拟内存中滑动的地址长度 (在mach文件中, 代码段定义的虚拟内存的地址和mach文件首地址是一样的, mh偏移后, 减去代码段文件中定义的虚拟内存首地址, 即可获得滑动地址)
	uintptr_t appsSlide = slideOfMainExecutable(appsMachHeader);
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
	mach_init();

	// set up random value for stack canary
	__guard_setup(apple);

	// setup gProcessInfo to point to host dyld's struct
	dyld::gProcessInfo = (struct dyld_all_image_infos*)(sc->getProcessInfo());
	syncProcessInfo();

	// now that we are done bootstrapping dyld, call dyld's main
	uintptr_t appsSlide = slideOfMainExecutable(mainExecutableMH);
	return dyld::_main(mainExecutableMH, appsSlide, argc, argv, envp, apple, startGlue);
}
#endif


} // end of namespace




