#ifndef __AXPERIAU_COMMON__
#define __AXPERIAU_COMMON__

#define DEVICE_NAME "Xperia U"

// for get proc address
typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);
static kallsyms_lookup_name_type kallsyms_lookup_name_ax;

#ifdef KERNEL_MODULE

#define OFS_KALLSYMS_LOOKUP_NAME 0xC00DB534 // kallsyms_lookup_name




//finding name in proc
static const struct file_operations dummy_ondemandx_operations = {
         .open = NULL,
         .read = seq_read,
         .llseek = seq_lseek,
         .release = seq_release_private,
};

#define PROC_FILE "kallsyms"
#define FILE_BUFFOR 100
#define TEXT_OFFSET 50
#define NAME_TO_FIND " T kallsyms_lookup_name"

static inline int file_open(struct file * file) {
	//create dummy proc	
	struct proc_dir_entry * dummy_entry = proc_create("dummy_ondemandx", 0444, NULL, &dummy_ondemandx_operations);
	if(dummy_entry == NULL)
		return -1;

	struct proc_dir_entry * parent = dummy_entry->parent;

	if(parent == NULL){
		return -1;
	}

	remove_proc_entry("dummy_ondemandx", NULL);

	struct proc_dir_entry * temp;

	for(temp = parent->subdir; temp != NULL ; temp = temp->next) {
		//loop thru files to find kallsyms

		if (strcmp(temp->name, PROC_FILE) == 0) {
			// if we have it - open it for us
			struct file_operations *proc_fops = temp->proc_fops;
			return proc_fops->open(NULL, file);
		}
	} 

	return -1;
}

static inline long findout_kallsyms_lookup_name(){
	long address = 0 ;
	long long position = 0;
	char buf[FILE_BUFFOR + 1];

	
	//prepare buffor
	memset(buf, FILE_BUFFOR, ' ');
	buf[FILE_BUFFOR] = 0;

	struct file file;
	memset(&file, 0, sizeof(struct file));

	//find kallsyms file in proc
	if(!file_open(&file)) {
		
		struct seq_file *p = file.private_data;
		if(p){
			struct seq_operations * kallsyms_op = p->op;
			if(kallsyms_op) {
				p->buf = buf;
				p->size = FILE_BUFFOR;
				
				//loop over data to find our func				
				void * data;
				for(data = kallsyms_op->start(p, &position); data; data = kallsyms_op->next(p, data, &position)) {
					p->count = 0;
					kallsyms_op->show(p, data);
					buf[p->count] = 0;
					
					if(strstr(buf, NAME_TO_FIND)){
						//find end of address
						printk("Found: %s\n", buf);				
						char * lastChar = buf;
						while(*lastChar != ' ' && *lastChar != 0 ){
							lastChar++;
						}
						lastChar[0] = 0;
						

						//convert it
						int ret;
						ret = sscanf(buf, "%lx", &address);
						break;
					}
				} 
			}
		}
	}

	return address;
}

#else //KERNEL_MODULE

#endif  //KERNEL_MODULE


#endif
