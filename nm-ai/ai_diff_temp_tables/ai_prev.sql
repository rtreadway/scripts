create table #prev as
SELECT * FROM {historic_schema_yearly}.ai_daily
	WHERE run_id = '{previous_ai_customer}';