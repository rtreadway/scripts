select p.ai_code, p.flag_name, p.original_value, p.transformed_value
from #parsed_recon_dq p
where p.message = 'Recon VS Daily character diff detected'
order by 1;