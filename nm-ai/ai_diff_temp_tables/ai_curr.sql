create table #curr as
SELECT * FROM {historic_schema_yearly}.ai_daily
	WHERE run_id= '{current_ai_daily}';