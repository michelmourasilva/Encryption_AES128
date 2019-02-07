create or replace function  AES128_STRING  (
   p_original_text   in   varchar2,
   p_key         		 in   varchar2,
   p_algorithm   		 in   varchar2 := 'AES128',   
   p_action          in   numeric -- (1) crypt (2) decrypt,   
)
   return varchar2  authid definer
/*
Objective: Masking of considerable sensitive information, eg; cpf and name
e.g:
select AES128_STRING('133467895421','1234567890123456', 'AES128',1) from dual; --(Condition of a string using AES128 algorithm)
select AES128_STRING('EB833824D0AA717F59D8899BE09582CF','1234567890123456', 'AES128', 2) from dual; --(Deconditioning of a string using AES128 algorithm)
select AES128_STRING('NAME LAST LANE','null', 'SUBS_STRING', 1) from dual; --(Mask a string by replacing all its characters with x)
select AES128_STRING('15789 7897','null', 'SUBS_NUMERIC', 1) from dual; --(Mask a string by replacing all its characters with 0)
select AES128_STRING('25/12/1980','null', 'SUBS_DATA', 1) from dual; --(Mask a string by replacing all its characters with 01/01/1900)
*/  

is
   v_changed_string      raw (4000);
   v_algorithm   		    pls_integer;
   v_original_text       raw (4000);
   v_initial_vector        raw (4000) := hextoraw('0000000000000000');
   v_key        		    raw (4000);
   v_return       		    varchar2 (4000);
begin   
      -- Defines which algorithm to use
      case p_algorithm
        when 'AES128'
            then v_algorithm := dbms_crypto.encrypt_aes128;
        when 'SUBS_STRING'
            then v_algorithm := 1; -- Replaces strings with X
        when 'SUBS_DATA'
            then v_algorithm := 2; -- Replaces strings with 01/01/1900
        when 'SUBS_NUMERIC'
            then v_algorithm := 3; -- Replaces strings with 0
        else
            raise_application_error(-20901,'Error: The encoding / decoding algorithm does not exist in the possible values.');
        end case;   
		if v_algorithm in (1,2,3) and p_action = 2 then
			raise_application_error(-20902,'Error: It is not possible to decode values ​​that used date, string, and numeric substitution algorithms.');
		end if;
   case p_action   
        when 1 then

                case v_algorithm
                    when 1 then
                       v_return := REGEXP_REPLACE(p_original_text, '\w', 'X');
                    when 2 then
                       v_return :=  to_date('01/01/1900', 'DD/MM/YYYY');                
                    when 3 then
                        v_return := REGEXP_REPLACE(p_original_text, '\w', '0');
                    else
                            v_original_text := utl_i18n.string_to_raw (p_original_text, 'AL32UTF8');
                            v_initial_vector := utl_i18n.string_to_raw (v_initial_vector, 'AL32UTF8');
                            v_key := utl_i18n.string_to_raw (p_key, 'AL32UTF8');
                            v_changed_string :=
                            dbms_crypto.encrypt (src        => v_original_text,
                                                key         => v_key,
                                                iv          => v_initial_vector,
                                                typ         => v_algorithm
                                                            + dbms_crypto.chain_cbc
                                                            + dbms_crypto.pad_pkcs5
                                              );
                       v_return := rawtohex (v_changed_string);                                
                end case;
        when 0 then     			
				v_original_text := hextoraw(p_original_text);               
				v_initial_vector := utl_i18n.string_to_raw (v_initial_vector, 'AL32UTF8');               
			    v_key := utl_i18n.string_to_raw (p_key, 'AL32UTF8');				
				v_changed_string :=
                dbms_crypto.decrypt (src    => v_original_text,
                               key          => v_key,
                               iv           => v_initial_vector,
                               typ          => v_algorithm
                                           + dbms_crypto.chain_cbc
                                           + dbms_crypto.pad_pkcs5
                              );
       v_return := utl_i18n.raw_to_char (v_changed_string, 'AL32UTF8');	   
    end case;
   return v_return;
exception
    when others then
        raise_application_error(-20001,'Erro: An unexpected error occurred while executing the function. Error: ' ||sqlcode||' -error- '||sqlerrm);
        return null;
end;