#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <yaml.h>
#define typename(x) _Generic((x),        /* Get the name of a type */             \
                                                                                  \
        _Bool: "_Bool",                  unsigned char: "unsigned char",          \
         char: "char",                     signed char: "signed char",            \
    short int: "short int",         unsigned short int: "unsigned short int",     \
          int: "int",                     unsigned int: "unsigned int",           \
     long int: "long int",           unsigned long int: "unsigned long int",      \
long long int: "long long int", unsigned long long int: "unsigned long long int", \
        float: "float",                         double: "double",                 \
  long double: "long double",                   char *: "pointer to char",        \
       void *: "pointer to void",                int *: "pointer to int",         \
      default: "other")

int main()
{
    FILE *fp = fopen("config.yaml","r");
    yaml_parser_t parser;
    yaml_event_t event;
    bool isKey =false;
    bool main_map = true;
    if(!yaml_parser_initialize(&parser))
        printf("Failed to initialize parser!\n");
    yaml_parser_set_input_file(&parser,fp);

    char keys[255];
    char mapping_name[255][1000];
    int mapping_index = 0;
    int a[4];

    //char pairValue[255];
    do
    {
        if(!yaml_parser_parse(&parser,&event)){
            printf("parser error %d\n",parser.error);
            exit(EXIT_FAILURE);
        }
        switch (event.type)
        {
        case YAML_NO_EVENT:printf("No event\n"); break;
        case YAML_STREAM_START_EVENT:printf("STRAT\n"); break;
        case YAML_STREAM_END_EVENT:printf("END\n"); break;
        //process delimeters
        case YAML_DOCUMENT_START_EVENT:printf("Main data\n"); break;
        case YAML_DOCUMENT_END_EVENT:printf("End of data\n"); break;
        case YAML_SEQUENCE_START_EVENT:printf("Start Sequence\n"); break;
        case YAML_SEQUENCE_END_EVENT:printf("End Sequence\n");break;
        case YAML_MAPPING_START_EVENT:
            printf("Start mapping\n");
            //printf("isKey %d\n",isKey);
            mapping_index++;
            if (!isKey && ! main_map){ 
                printf("\tMapping name--->%s\n",keys);
                sprintf(mapping_name[mapping_index],"%s",keys);
            }
            else{
                main_map = false;
                sprintf(mapping_name[mapping_index],"main");
            }
            isKey = true;
            break;
        case YAML_MAPPING_END_EVENT:
            printf("End mapping: %s\n",mapping_name[mapping_index]);
            mapping_index--;
            break;
        //data
        case YAML_ALIAS_EVENT:
            printf("Alias (anchor %s)\n",event.data.alias.anchor);
            break;
        case YAML_SCALAR_EVENT:
            if (isKey)
            {
                //printf("%s\n",event.data.scalar.value);
                sprintf(keys,"%s",event.data.scalar.value);
                if (!strcmp(mapping_name[mapping_index],"basic_limit"))
                {
                    int i=0;
                    char *token = strtok(event.data.scalar.value,".");
                    while (token != NULL)
                    {
                        a[i] = strtol(token,NULL,10);
                        token = strtok(NULL,".");
                        i++;
                    }
                    
                }              
                isKey=false;
            }
            else{ 
                isKey=true;
                if (keys == "num_rules"){
                    printf("%s----->%d\n",keys,strtol(event.data.scalar.value,NULL,10));
                }
                else if (keys == "time_interval")
                {
                    printf("%s----->%f\n",keys,strtof(event.data.scalar.value,NULL));
                }
                else
                {
                    printf("%s----->%s\n",keys,event.data.scalar.value);
                }
            }
            break;
        default: break;
        }
        if (event.type != YAML_STREAM_END_EVENT)
        {
            yaml_event_delete(&event);
        }
        
    } while (event.type != YAML_STREAM_END_EVENT);
    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fp);
    return 0;
}