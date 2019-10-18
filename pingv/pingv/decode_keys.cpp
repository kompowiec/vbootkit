#include <stdio.h>


// Unshifted characters
unsigned char unshifted[][2] = {
0x0d,9,
0x0e,'|',
0x15,'q',
0x16,'1',
0x1a,'z',
0x1b,'s',
0x1c,'a',
0x1d,'w',
0x1e,'2',
0x21,'c',
0x22,'x',
0x23,'d',
0x24,'e',
0x25,'4',
0x26,'3',
0x29,' ',
0x2a,'v',
0x2b,'f',
0x2c,'t',
0x2d,'r',
0x2e,'5',
0x31,'n',
0x32,'b',
0x33,'h',
0x34,'g',
0x35,'y',
0x36,'6',
0x39,',',
0x3a,'m',
0x3b,'j',
0x3c,'u',
0x3d,'7',
0x3e,'8',
0x41,',',
0x42,'k',
0x43,'i',
0x44,'o',
0x45,'0',
0x46,'9',
0x49,'.',
0x4a,'-',
0x4b,'l',
0x4c,'ø',
0x4d,'p',
0x4e,'+',
0x52,'æ',
0x54,'å',
0x55,'\\',
0x5a,13, 
0x5b,'¨',
0x5d,'\'',
0x61,'<',
0x66,8,
0x69,'1',
0x6b,'4',
0x6c,'7',
0x70,'0',
0x71,',',
0x72,'2',
0x73,'5',
0x74,'6',
0x75,'8',
0x79,'+',
0x7a,'3',
0x7b,'-',
0x7c,'*',
0x7d,'9',
0,0
};



unsigned char shifted[][2] = {
0x0d,9,
0x0e,'§',
0x15,'Q',
0x16,'!',
0x1a,'Z',
0x1b,'S',
0x1c,'A',
0x1d,'W',
0x1e,'"',
0x21,'C',
0x22,'X',
0x23,'D',
0x24,'E',
0x25,'¤',
0x26,'#',
0x29,' ',
0x2a,'V',
0x2b,'F',
0x2c,'T',
0x2d,'R',
0x2e,'%',
0x31,'N',
0x32,'B',
0x33,'H',
0x34,'G',
0x35,'Y',
0x36,'&',
0x39,'L',
0x3a,'M',
0x3b,'J',
0x3c,'U',
0x3d,'/',
0x3e,'(',
0x41,';',
0x42,'K',
0x43,'I',
0x44,'O',
0x45,'=',
0x46,')',
0x49,':',
0x4a,'_',
0x4b,'L',
0x4c,'Ø',
0x4d,'P',
0x4e,'?',
0x52,'Æ',
0x54,'Å',
0x55,'`',
0x5a,13, 
0x5b,'^',
0x5d,'*',
0x61,'>',
0x66,8,
0x69,'1',
0x6b,'4',
0x6c,'7',
0x70,'0',
0x71,',',
0x72,'2',
0x73,'5',
0x74,'6',
0x75,'8',
0x79,'+',
0x7a,'3',
0x7b,'-',
0x7c,'*',
0x7d,'9',
0,0
};



unsigned char is_up=0, shift = 0, mode = 0;
   

void DecodeAndPrintKeyLog(unsigned int len,unsigned char*log)
{





	unsigned char loop_var;

	for(loop_var = 0 ;loop_var < len;loop_var++)
	{
			unsigned char scancode = *log;
			char sc = *log;

			unsigned char c = 0;
			log++;
			
			if ( sc > 0x80)
				continue;



	switch(sc) {
			

 case 29: printf ("`");// shift  ~
break; 
 case 2: printf ("1/!");
break; 
 case 3: printf ("2/@");
break; 
 case 4:	printf ("3 #");
break; 
 case 5: printf ("4 $");
break; 
 case 6	: printf ("5 % E");
break; 
 case 7: printf ("6 ^");
break; 
 case 8:	 printf ("7 &");
break; 
 case 9:	 printf ("8 *");
break; 
 case 0x0a : printf ("9 (");
break; 
 case 0x0b : printf ("0 )");
break; 
 case 0x0c: printf (" #NAME?");
break; 
 case 0x0d : printf ("= +");
break; 
 case 0x0e : printf ("Backspace");
break; 
 case 0x0f 	: printf ("Tab");
break; 
 case 0x10: printf ("Q");
break; 
 case 0x11	: printf ("W");
break; 
 case 0x12: printf ("E");
break; 
 case 0x13	: printf ("R");
break; 
 case 0x14	: printf ("T");
break; 
 case 0x15	: printf ("Y");
break; 
 case 0x16	: printf ("U");
break; 
 case 0x17	: printf ("I");
break; 
 case 0x18	: printf ("O");
break; 
 case 0x19: printf ("P");
break; 
 case 0x1a : printf ("[ {");
break; 
 case 0x1b : printf ("] }");
break; 
 case 0x2b 	: printf ("\\ |");
break; 
 case 0x3a : printf ("CapsLock");
break; 
 case 0x1e : printf ("A");
break; 
 case 0x1f : printf ("S");
break; 
 case 0x20: printf ("D");
break; 
 case 0x21	: printf ("F");
break; 
 case 0x22: printf ("G");
break; 
 case 0x23: printf ("H");
break; 
 case 0x24	: printf ("J");
break; 
 case 0x25	: printf ("K");
break; 
 case 0x26: printf ("L");
break; 
 case 0x27	: printf ("; :");
break; 
 case 0x28: printf ("' \"");
break; 
 case 0x0: printf ("	non-US-1");
break; 
 case 0x1c: printf (" Enter");
break; 
 case 0x2a : printf ("LShift");
break; 
 case 0x2c : printf ("Z");
break; 
 case 0x2d : printf ("X");
break; 
 case 0x2e : printf ("C");
break; 
 case 0x2f : printf ("V");
break; 
 case 0x30	: printf ("B");
break; 
 case 0x31	: printf ("N");
break; 
 case 0x32: printf ("M");
break; 
 case 0x33: printf (", <");
break; 
 case 0x34: printf (". >");
break; 
 case 0x35: printf ("/ ?");
break; 
 case 0x36: printf ("RShift");
break; 
 case 0x37 : printf ("LCtrl");
break; 
 case 0x38: printf ("LAlt");
break; 
 case 0x39: printf ("space");
break; 
 /*case e0-38 	RAlt
break; 
 /case e0-1d 	RCtrl
break; 
 case e0-52 	Insert
break; 
 case e0-53 	Delete
break; 
 case e0-47 	Home
break; 
 case e0-4f 	End
break; 
 case e0-49 	PgUp
break; 
 case e0-51 	PgDn
break; 
 case e0-4b 	Left
break; 
 case e0-48 	Up
break; 
 case e0-50 	Down
break; 
 case e0-4d 	Right
break; 

 case 0x45	NumLock
break; 
 case 0x47	KP-7 / Home
break; 
 case 0x4b 	KP-4 / Left
break; 
 case 0x4f 	KP-1 / End
break; 
 //case e0-35 	KP-/
//break; 
 case 0x48	KP-8 / Up
break; 
 case 0x4c 	KP-5
break; 
 case 0x50	KP-2 / Down
break; 
 case 0x52	KP-0 / Ins
break; 
 case 0x37	KP-*
break; 
 case 0x49	KP-9 / PgUp
break; 
 case 0x4d 	KP-6 / Right
break; 
 case 0x51	KP-3 / PgDn
break; 
 case 0x53	KP-. / Del
break; 
 case 0x4a 	KP--
break; 
 case 0x4e 	KP-+
break; 
 case 0xe0-1c 	KP-Enter
break; 
 case 0x1	Esc
break; 
*/
 case 0x3b : printf ("F1");
break; 
 case 0x3c : printf ("F2");
break; 
 case 0x3d: printf ("F3");
break; 
 case 0x3e : printf ("F4");
break; 
 case 0x3f : printf ("F5");
break; 
 case 0x40: printf ("F6");
break; 
 case 0x41: printf ("F7");
break; 
 case 0x42: printf ("F8");
break; 
 case 0x43	: printf ("F9");
break; 
 case 0x44	: printf ("F10");
break; 
 case 0x57: printf ("F11");
break; 
 case 0x58	: printf ("F12");
break; 
	 /*
 case e0-37 	PrtScr
break; 
 case 54	Alt+SysRq
break; 
 case 46	ScrollLock
break; 
 case e1-1d-45 	Pause
break; 
 case e0-46 	Ctrl+Break
break; 
 case e0-5b 	LWin (USB: LGUI)
break; 
 case e0-5c 	RWin (USB: RGUI)
break; 
 case e0-5d 	Menu
break; 
 case e0-5f 	Sleep
break; 
 case e0-5e 	Power
break; 
 case e0-63 	Wake 
break; 
 */ 
			}

}
        } 
