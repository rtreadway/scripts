select 
dq.ai_code,
dq.sname,
dq.flag_name,
dq.original_value,
dq.transformed_value,
length(dq.original_value) as original_len
from #parsed_recon_dq dq
where dq.message = 'Recon VS Daily length diff detected'
and dq.pn_country = 'US'
and dq.ai_code not in (
	select ai_code from #parsed_recon_dq where message = 'Recon VS Daily character diff detected'
)
order by dq.flag_name, dq.ai_code