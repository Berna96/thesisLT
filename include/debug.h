void debug(){
        fprintf(stderr,"[DEBUG] step\n");
        fflush(stderr);
}

void pdebug(void* pointer){
	printf("[DEBUG]Address : 0x%08x\n", (unsigned int) pointer);
}

