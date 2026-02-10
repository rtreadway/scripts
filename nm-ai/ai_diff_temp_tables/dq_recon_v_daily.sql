create table #parsed_recon_dq as
select 
	ad.ai_code,
	dq.primary_key,
	trim(split_part(dq.primary_key, '-', 1)) as dq_ai_cd,
	trim(split_part(dq.primary_key, '-', 2)) as ai_source_cd,
	dq.flag_name,
	dq.message,
	dq.value,
	trim(split_part(dq.value, '|', 1)) AS original_value,
	trim(split_part(dq.value, '|', 2)) AS transformed_value,
	dq.record_version,
	dq.record_timestamp,
	dq.update_timestamp,
	ad."name",
	ad.sname,
	ad.pn_country,
	ad.ship_country,
	ad.run_id
from {current_schema_all}.ai_data_quality dq
join {historic_schema_yearly}.ai_daily ad on trim(split_part(dq.primary_key, '-', 1)) = ad.ai_code
where dq.message like 'Recon VS Daily%'
and ad.run_id = '{current_ai_daily}'