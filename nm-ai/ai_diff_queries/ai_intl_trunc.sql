select 
case when dq.flag_name = 'PN_ADDRESS_LINE1' then 'Address Line 1'
	when dq.flag_name = 'PN_ADDRESS_LINE2' then 'Address Line 2'
	when dq.flag_name = 'PN_ADDRESS_CITY' then 'Address City'
	else null
	end as field,
dq.ai_code,
dq.original_value as full,
length(dq.original_value) as value_len,
dq.transformed_value as transformed
from #parsed_recon_dq dq
join team_rp__nm_current_all.ai_all_fields aaf on dq.ai_code = aaf.ai_cd
where dq.message = 'Recon VS Daily length diff detected'
and dq.pn_country != 'US'
and field is not null
and dq.ai_code not in (
	select ai_code from #parsed_recon_dq where message = 'Recon VS Daily character diff detected'
)
and aaf.nm_reportable_ind = 'Y'
order by field, dq.ai_code