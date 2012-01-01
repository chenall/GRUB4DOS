/* graphics.h - graphics console interface */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef GRAPHICS_H
#define GRAPHICS_H
#define SPLASH_BASE_ADDR (splashimage_loaded & ~0xfL)
#define SPLASH_W (*(unsigned long *)SPLASH_BASE_ADDR)
#define SPLASH_H (*(unsigned long *)(SPLASH_BASE_ADDR+4))
#define SPLASH_IMAGE ((unsigned long*)(SPLASH_BASE_ADDR+0x10))
#endif /* GRAPHICS_H */
