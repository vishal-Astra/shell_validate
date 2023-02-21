bool validate_shell_cmd(char *user_shell_cmd,  char *final_cmd,
                          int final_cmd_max_len, struct vty *vty, int *pat_count_ptr)
  {
     char *ptr = NULL, *ptr1 = NULL, *ptr2 = NULL, *ptr3 = NULL;
     char word_buf[MAX_BUF_LEN], str[5], tmp_buf[MAX_BUF_LEN];
     char revStr_redirect_line_count[MAX_BUF_LEN];
     int count, pid;
     bool flag_substr = false;
     int ret_cmp = 0, j;
     int cmd_len = 0;
     int count_occurence = 0;
     int pat_count = 0;
     enum shell_commands command_str;
     char *shell_commands_supported[MAX_SHELL_CMD_ALLOWED] =
                             {"include", "exclude",
                                "count", "begin", "line-number", "redirect"};
     int line_count = 0;
  
     memset(final_cmd, 0, final_cmd_max_len);
     memset(word_buf, 0, MAX_BUF_LEN);
     memset(tmp_buf, 0, MAX_BUF_LEN);
     memset(str, 0, 5);
  
     command_str = UNKNOWN_CMD;
  
     for(ptr = user_shell_cmd; *ptr != '\0'; ptr++)         // The first for loop scans through the user input string and checks for certain characters that should not appear in a command. If any of these characters are found, the function returns false. This is a simple security check to prevent certain types of malicious or unintended commands.
     { 
        if(*ptr == '&' || *ptr == ';' ||
            *ptr == '\'' || *ptr == '>'|| *ptr == '<')
        {
           return FALSE;
        }
     }
  
     ptr = user_shell_cmd;
  
     if(begin_redirect_line_count) {
        int digit = 0;
        int index = 0;
        memset(revStr_redirect_line_count, 0, MAX_BUF_LEN);
  
        while (begin_redirect_line_count > 0) {
           digit = begin_redirect_line_count % 10;
           revStr_redirect_line_count[index] = digit +'0';
           begin_redirect_line_count = begin_redirect_line_count / 10;
           index++;
       }
        int revStr_len = strlen(revStr_redirect_line_count);
        index = 0;
        char temp;
        while(index < revStr_len) {
           temp = revStr_redirect_line_count[index];
           revStr_redirect_line_count[index] = revStr_redirect_line_count[revStr_len-1];
           revStr_redirect_line_count[revStr_len-1] = temp;
           index++;
           revStr_len--;
        }
     }
  
     do
     {
        while(isspace(*ptr))
           ptr++;
  
        if(*ptr == '|')
        {
           strncat(final_cmd, "|", 1);
           ptr++;
        }
        count = 0;
  
        while(isspace(*ptr))
          ptr++;
  
        ptr1 = ptr;
  
        while( *ptr1 != ' ' && *ptr1 != '\0')
        {
           *ptr1 = tolower((unsigned char) *ptr1);
           ptr1++;
           count++;
       }
  
        memset(word_buf, 0, MAX_BUF_LEN);
  
        if ( count >= MAX_BUF_LEN )
        {
           VLOG_ERR("Pipe:Max command length exceeded\n");
           return FALSE;
        } else {
           strlcpy(word_buf, ptr, count+1);
       }
  
        ptr = ptr1;
        for(j = 0; j < MAX_SHELL_CMD_ALLOWED; j++)
        {
           ret_cmp = strncmp(word_buf, shell_commands_supported[j],
                   count);
           if(ret_cmp == 0)
           {
              command_str = j;
              break;           }
           ptr3 = strstr(shell_commands_supported[j],word_buf);
           if(ptr3 ==(char*) &shell_commands_supported[j])
           {
              flag_substr = true;
              break;
           }
        }
        if(ret_cmp != 0 && !(flag_substr))
        {
          return FALSE;
        }
  
        while(isspace(*ptr))
           ptr++;
  
        switch (command_str)
        {
           case INCLUDE:
              strncat(final_cmd, " grep -F -f ", strlen(" grep -F -f "));
              ptr1 = ptr;              count = 0;
  
              count = extract_pattern_str(ptr1);
  
              if(count == 0)
                 return FALSE;
  
              ptr1 = ptr1 + count;
  
              if(*ptr1 == ' ')
              {
                 while (isspace(*ptr1))
                    ptr1++;
              }
  
              if ((*ptr1 != '\0') && (*ptr1 != '|'))
                 return FALSE;
  
              memset(word_buf, 0, MAX_BUF_LEN);
              memset(tmp_buf, 0, MAX_BUF_LEN);
              if ( count >= MAX_BUF_LEN )
             {
                 VLOG_ERR("Pipe:Max command length exceeded\n");
                 return FALSE;
              } else {
                 strlcpy(word_buf, ptr, count+1);
              }
  
              *pat_count_ptr = ++pat_count;
              snprintf(tmp_buf, MAX_BUF_LEN, "%s%x_%d", VTYSH_PIPE_TMP_FILE,
                       getpid(), pat_count);
              if(create_pat_file(tmp_buf, word_buf) == FALSE)
                  return FALSE;
  
              strncat(final_cmd, tmp_buf, strlen(tmp_buf));
              VLOG_DBG("Pipe: Include cmd used as %s", final_cmd);
  
              break;
  
           case EXCLUDE:
              strncat(final_cmd, " grep -F -v -f ", strlen(" grep -F -v -f "));
              ptr1 = ptr;
              count = 0;
  
              count = extract_pattern_str(ptr1);
  
              if(count == 0)
                 return FALSE;
  
              ptr1 = ptr1 + count;
  
              if(*ptr1 == ' ')
              {
                 while (isspace(*ptr1))
                 ptr1++;
              }
  
              if ((*ptr1 != '\0') && (*ptr1 != '|'))
                 return FALSE;
 
              memset(word_buf, 0, MAX_BUF_LEN);
              memset(tmp_buf, 0, MAX_BUF_LEN);
              if ( count >= MAX_BUF_LEN )
              {
                 VLOG_ERR("Pipe:Max command length exceeded\n");
                 return FALSE;
             } else {
                 strlcpy(word_buf, ptr, count+1);
              }
  
              *pat_count_ptr = ++pat_count;
              snprintf(tmp_buf, MAX_BUF_LEN, "%s%x_%d", VTYSH_PIPE_TMP_FILE,
                       getpid(), pat_count);
              if(create_pat_file(tmp_buf, word_buf) == FALSE)
                  return FALSE;
  
              strncat(final_cmd, tmp_buf, strlen(tmp_buf));
              VLOG_DBG("Pipe: Exclude cmd used as %s", final_cmd);
  
              break;
  
           case COUNT:
              count_occurence++;
            if (count_occurence > 1)
              {
                 return FALSE;
              }
              ptr1 = ptr;
              count = 0;
  
              count = extract_pattern_str(ptr1);
              ptr1 = ptr1 + count;
  
              if(*ptr1 == ' ')
              {
                 while (isspace(*ptr1))
                    ptr1++;
              }
  
              if ((*ptr1 != '\0') && (*ptr1 != '|'))
                return FALSE;
  
              if(count != 0)
              {
                 strncat(final_cmd, " grep -F -c -f ", strlen(" grep -F -c -f "));
  
                 memset(word_buf, 0, MAX_BUF_LEN);
                 memset(tmp_buf, 0, MAX_BUF_LEN);
                 if ( count >= MAX_BUF_LEN )
                 {
                     VLOG_ERR("Pipe:Max command length exceeded\n");
                     return FALSE;
                 } else {
                     strlcpy(word_buf, ptr, count+1);
                 }
  
                 *pat_count_ptr = ++pat_count;
                 snprintf(tmp_buf, MAX_BUF_LEN, "%s%x_%d", VTYSH_PIPE_TMP_FILE,
                          getpid(), pat_count);
                 if(create_pat_file(tmp_buf, word_buf) == FALSE)
                     return FALSE;
  
                 strncat(final_cmd, tmp_buf, strlen(tmp_buf));
              }
              else
              {
                 cmd_len = strlen(final_cmd);
                 if (final_cmd[cmd_len - 1] == '|')
                    final_cmd[cmd_len - 1] = '\0';
                 strncat(final_cmd,"| wc -l ", strlen("| wc -l "));
              }
              VLOG_DBG("Pipe: Count cmd used as %s", final_cmd);
  
              break;
  
           case BEGIN:
              strncat(final_cmd, " grep --no-group-separator -F ",
                          strlen(" grep --no-group-separator -F "));
              ptr1 = ptr;
              count = 0;
              int num;
  
              while(*ptr1 != '\0' && *ptr1 != '|') {
                 ptr1++;
                 count++;
              }
  
              if(count == 0 || count > MAX_BUF_LEN)
                 return FALSE;
  
              ptr1 = ptr;
  
              /* if shell-cmd has the cmd like begin "pattern-string"
               * if part will hit and form the final cmd
               * else if shell-cmd has the cmd like begin pattern-string or
               * begin positive-num pattern-string or
               * begin negative-num pattern-string
               * else part will hit
               */
              if(*ptr1 == '\"') {
                 strncat(final_cmd,"-A ", strlen("-A "));
                 strncat(final_cmd, revStr_redirect_line_count,
                        strlen(revStr_redirect_line_count));
                strncat(final_cmd, " ", strlen(" "));
            } else {
                 int i = 0, j = 0;
                 char buf1[MAX_BUF_LEN], buf2[MAX_BUF_LEN];
                 memset(buf1, 0, MAX_BUF_LEN);
                 memset(buf2, 0, MAX_BUF_LEN);
                 bool flag = FALSE;
                 /* buf1 is for storing the first word till space
                  * buf2 is for storing the word after space
                  */
                 while(*ptr1 != '\0' && *ptr1 != '|') {
                    if(*ptr1 == ' ') {
                       flag = TRUE;
                    }
                    if(flag == FALSE) {
                       *(buf1+i) = *ptr1;
                      i++;
                    } else {
                       if(flag == TRUE && *ptr1 != ' ') {
                          *(buf2+j) = *ptr1;
                          j++;
                       }
                    }
                  ptr1++;
                 }
  
                 ptr1 = ptr;
  
                /* if the shell-cmd has begin pattern-string
                  * will form the final_cmd in if part else will
                  * continue to else part
                  */
                 if(strlen(buf1) != 0 && strlen(buf2) == 0) {
                    strncat(final_cmd,"-A ", strlen("-A "));
                    strncat(final_cmd, revStr_redirect_line_count,
                           strlen(revStr_redirect_line_count));
                    strncat(final_cmd, " ", strlen(" "));
                 } else {
                    if(strlen(buf1) != 0 && strlen(buf2) != 0) {
                       count = 0;
                       while(isspace(*ptr1))
                          ptr1++;
                      if(*ptr1 == '-') {
                          ptr1++;
                          count++;
                       }
                       while( (*ptr1 != ' ') && (*ptr1 != '|') && (*ptr1 != '\0')) {
                         if (!(isdigit((int) *ptr1)))
                             return FALSE;
                          ptr1++;
                          count++;
                       }
                       if((count == 0) || (*ptr1 == '|') || (*ptr1 == '\0'))
                          return FALSE;
  
                       memset(word_buf, 0, MAX_BUF_LEN);
                       if ( count >= MAX_BUF_LEN )
                       {
                          VLOG_ERR("Pipe:Max command length exceeded\n");
                          return FALSE;
                       } else {
                          strlcpy(word_buf, ptr, count+1);
                          num = atoi(word_buf);
                       }
                       if (*ptr1 == ' ')
                          word_buf[count] = ' ';
                       if(num < 0) {
                          /* if the shell-cmd has negative num after begin
                           * form final_cmd by appending -B
                           */
                          strncat(final_cmd, "-B ", strlen("-B "));
                          int i = 0;
                          while ( word_buf[i]!='\0') {
                             word_buf[i] = word_buf[i+1];
                             i++;
                          }
                          strncat(final_cmd, word_buf, strlen(word_buf));
                       } else {
                         /* if the shell-cmd has positive num after begin
                          * form final_cmd by appending -A
                          */
                        strncat(final_cmd, "-A ", strlen("-A "));
                         strncat(final_cmd, word_buf, strlen(word_buf));
                       }
                       count = 0;
                      ptr1++;
                       while (isspace(*ptr1))
                        ptr1++;
                    }
               }
              }
              ptr2 = ptr1;
  
              count = extract_pattern_str(ptr2);
  
              if(count == 0)
                 return FALSE;
  
              ptr2 = ptr2 + count;
             if(*ptr2 == ' ')
              {
                 while (isspace(*ptr2))
                    ptr2++;
              }
  
              if ((*ptr2 != '\0') && (*ptr2 != '|'))
                 return FALSE;
  
              memset(word_buf, 0, MAX_BUF_LEN);
              memset(tmp_buf, 0, MAX_BUF_LEN);
              if ( count >= MAX_BUF_LEN )
              {
                 VLOG_ERR("Pipe:Max command length exceeded\n");
                 return FALSE;
              } else {
                 strlcpy(word_buf, ptr1, count+1);
              }
  
              *pat_count_ptr = ++pat_count;
              snprintf(tmp_buf, MAX_BUF_LEN, "%s%x_%d", VTYSH_PIPE_TMP_FILE,
                       getpid(), pat_count);
              if(create_pat_file(tmp_buf, word_buf) == FALSE)
                  return FALSE;
  
              strncat(final_cmd, "-f ", strlen("-f "));
              strncat(final_cmd, tmp_buf, strlen(tmp_buf));
              VLOG_DBG("Pipe: Begin cmd used as %s", final_cmd);
  
              break;
  
           case LINE_NUMBER:
              line_count++;
              if(line_count > 1) {
                 return FALSE;
              }
  
              ptr1 = ptr;
  
              while (isspace(*ptr1)) {
                    ptr1++;
              }
  
              if ((*ptr1 != '|') && (*ptr1 != '\0'))
                 return FALSE;
  
              strncat(final_cmd, " cat -n ", strlen(" cat -n "));
  
              break;
  
           case REDIRECT:
              redirect_flag = 1;
             pid = getpid();
              umask(0022);
 
              cmd_len = strlen(final_cmd);
             if (cmd_len > 0 && final_cmd[cmd_len - 1] == '|')
                 final_cmd[cmd_len - 1] = '\0';
  
              strncat(final_cmd, " > /tmp/", strlen(" > /tmp/"));
              while (isspace(*ptr))
                 ptr++;
              ptr1 = ptr;
  
              /* redirect doesn't support use of '/' in command and
                 direcory redirect is not allowed hence return false */
              if (strstr(ptr, "/"))
                 return false;
  
              count = 0;
              snprintf(str, 5, "%d", pid);
  
              if(!(*ptr1))
              {
                 strncat(final_cmd, "pipe-redirect-output-",
                         strlen("pipe-redirect-output-"));
                 strncat(final_cmd, str, strlen(str));
                 strncat(final_cmd, ".txt", strlen(".txt"));
              }
              else
              {
                 count = extract_pattern_str(ptr1);
  
                 ptr1 = ptr1 + count;
                 if ((*ptr1 == '|') || (count == 0))
                    return FALSE;
  
                 if(*ptr1 == ' ')
                 {
                   while (isspace(*ptr1))
                    ptr1++;
                 }
                 if ((*ptr1 != '\0') && (*ptr1 != '|'))
                    return FALSE;
  
                 memset(word_buf, 0, MAX_BUF_LEN);
                if ( strlcpy(word_buf, ptr, sizeof(word_buf)) >= MAX_BUF_LEN )
                 {
                   VLOG_ERR("Pipe:Max command length exceeded\n");
                    return FALSE;
                 }
                 strncat(final_cmd, word_buf, strlen(word_buf));
              }
              VLOG_DBG("Pipe: Redirect cmd used as %s", final_cmd);
              break;
  
           default:
              return FALSE;
        }
        while(*ptr != '|')
        {
           if(*ptr == '\0')
              return TRUE;
           ptr++;
        }
     }while(*ptr == '|');
     return TRUE;
}
