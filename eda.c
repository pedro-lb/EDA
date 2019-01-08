/* TODO:
 * 	typewriter effect module 
 * 	ASCII art randomyzer
 * 	md5 encoding
 * 	md4 encoding
 * 	ROT13 encoding/decoding
 * 	Caesar's Cypher module
 */ 

/*
 *------------------------------------------*
 *		 ________  ______        _       	*
 *		|_   __  ||_   _ `.     / \      	*
 *		  | |_ \_|  | | `. \   / _ \     	*
 *		  |  _| _   | |  | |  / ___ \    	*
 *		 _| |__/ | _| |_.' /_/ /   \ \_  	*
 *		|________||______.'|____| |____| 	*
 *  	Encoding and Decoding Assistant		*
 *  Free and Open-Source licensed under GPL *
 *  	Developed by Pedro Bini - Brazil	*
 * 		  Dev Started at 20/09/2016  		*
 *------------------------------------------*
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <assert.h>

const char *argp_program_version = "v0.5";
static char doc[] = "EDA [Encoding and Decoding Assistant] is a tool to help easily deal with various encoding and decoding formats.";
static char args_doc[] = "[value]";

//Used for repeating
int repeat_aux = 1;
char* buffer;

//Used in base64 decoding
unsigned char* base64d_output;
size_t size;

//Used in base64 encoding
char* base64e_output;

static struct argp_option options[] = { 
	{ "base64-decode ", 'd', " [hash]", 0, "Decode from base64"},
	{ "base64-encode ", 'e', " [hash]", 0, "Encode to base64"},
	{ "rot13", 0, " [hash]", 0, "Encode/Decode to/from ROT13"},
	{ "md4 ", 0, " [hash]", 0, "Encode to md4"},
	{ "md5 ", 0, " [hash]", 0, "Encode to md5"},
	{ "repeat ", 'r', " [n]", 0, "Repeats the process n times"},
	{ "verbose", 'v', 0, 0, "Verbose mode -- shows more info"},	
    { 0 } 
};

struct arguments {
    enum { empty, BASE64_ENCODE, BASE64_DECODE, MD5_ENCODE, MD4_ENCODE } mode;    
    int VERBOSE, REPEAT, REPEAT_N;   
    char *data;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;    
    switch (key) {
		case 'd': 
			arguments->mode = BASE64_DECODE; 			
			arguments->data = arg;
			break;
		case 'e': 
			arguments->mode = BASE64_ENCODE;
			arguments->data = arg;
			break;
		case 'v': 
			arguments->VERBOSE = 1; 
			break;  		
		case 'r': 
			arguments->REPEAT = 1; 
			arguments->REPEAT_N = atoi(arg);
			break;		
		case ARGP_KEY_ARG: 
			return 0;
		case ARGP_KEY_END:			
			if (state->arg_num == 0 && strcmp(arguments->data, "[NULL]") == 0)
				argp_usage (state);
			break;
		default: 
			return ARGP_ERR_UNKNOWN;
    }   
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

size_t calcDecodeLength(const char* b64input) {
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=')
		padding = 2;
	else if (b64input[len-1] == '=')
		padding = 1;

	return (len*3)/4 - padding;
}

int base64Decode(char* b64message, unsigned char** buffer, size_t* length) {
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	*length = BIO_read(bio, *buffer, strlen(b64message));
	assert(*length == decodeLen);
	BIO_free_all(bio);

	return (0);
} 

int base64Encode(const char* buffer, size_t length, char** b64text) {
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text=(*bufferPtr).data;	

	return (0);
}
																								
void wascii ()
{	
	printf("\033[2J\033[1;1H"); //clear terminal screen
	printf ("   ________  ______        _       \n");
	printf ("  |_   __  ||_   _ `.     / \\      \n");	
	printf ("    | |_ \\_|  | | `. \\   / _ \\     \n");
	printf ("    |  _| _   | |  | |  / ___ \\    \n");
	printf ("   _| |__/ | _| |_.' /_/ /   \\ \\_  \n");
	printf ("  |________||______.'|____| |____| \n");
	printf ("Encoding and Decoding Assistant %s\n\n", argp_program_version);		
}	

int main (int argc, char *argv[])
{	
	wascii();	
	
	struct arguments arguments;

    arguments.mode = empty;    
    arguments.VERBOSE = 0;
    arguments.REPEAT = 0;
    arguments.REPEAT_N = 0;
    arguments.data = "[NULL]";    

    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    
    //check if the program should do anything based on arguments
    if (arguments.mode != empty) {			
		
		if (arguments.VERBOSE == 1) {
			printf ("[+] Running on verbose mode.\n\n[+]Arguments:\n");
			if (arguments.REPEAT ==1)
				printf ("  [-]Repeat for %d times\n  [-]Mode: ", arguments.REPEAT_N);
			else 
				printf ("  [-]Repeat is disabled\n  [-]Mode: ");
		}
		
		//base64 encoding or decoding -- no repeat
		if (arguments.REPEAT == 0 && (arguments.mode == BASE64_DECODE || arguments.mode == BASE64_ENCODE)) {			
			if (arguments.mode == BASE64_DECODE && arguments.VERBOSE == 1)
				printf("BASE64_DECODE\n\n");			
			else if (arguments.mode == BASE64_ENCODE && arguments.VERBOSE == 1)
				printf("BASE64_ENCODE\n\n");			
				
			printf ("[+]Input: \"%s\"",arguments.data);	
			if (arguments.mode == BASE64_DECODE) {
				printf ("\n ~ Decoding...\n");	
				base64Decode(arguments.data, &base64d_output, &size);			
				printf ("\n[+]Output: \"%s\"", base64d_output);	
				printf ("\n ~ Done!\n");
			}				
			else if (arguments.mode == BASE64_ENCODE) {
				printf ("\n ~ Encoding...\n");	
				base64Encode(arguments.data, strlen(arguments.data), &base64e_output);
				printf ("\n[+]Output: \"%s\"", base64e_output);	
				printf ("\n ~ Done!\n");
			}
			printf ("\n");
		}
		//base64 encoding or decoding -- repeating n times
		else if (arguments.REPEAT == 1 && (arguments.mode == BASE64_DECODE || arguments.mode == BASE64_ENCODE)) {
			if (arguments.mode == BASE64_DECODE && arguments.VERBOSE == 1)
				printf("BASE64_DECODE\n\n");			
			else if (arguments.mode == BASE64_ENCODE && arguments.VERBOSE == 1)
				printf("BASE64_ENCODE\n\n");			
						
			printf ("[+]Input: \"%s\"",arguments.data);	
								
			if (arguments.mode == BASE64_DECODE) {				
				printf ("\n ~ Decoding...\n");	
				buffer = arguments.data;
				for (repeat_aux = 1; repeat_aux < (arguments.REPEAT_N + 1); repeat_aux++) {					
					base64Decode(buffer, &base64d_output, &size);			
					printf ("\n[+]Output(%d): \"%s\"\n", repeat_aux, base64d_output);						
					//buffer = base64d_output;				
				}
				printf (" ~ Done!\n");
			}				
			else if (arguments.mode == BASE64_ENCODE) {
				printf ("\n ~ Encoding...\n");				
				base64e_output = arguments.data;
				for (repeat_aux = 1; repeat_aux < (arguments.REPEAT_N + 1); repeat_aux++) {											
					base64Encode(base64e_output, strlen(base64e_output), &base64e_output);
					printf ("\n[+]Output(%d): \"%s\"\n", repeat_aux, base64e_output);					
				}			
				printf (" ~ Done!\n");
			}
			printf ("\n");
		}
	}
		
	return 0;
}
