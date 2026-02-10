-- Debug query to test the individual parts
-- Test 1: Check if both tables have data
SELECT 'latest_record' as table_name, count(*) as row_count 
FROM {historic_schema_yearly}.ai_daily
WHERE run_id = '{current_ai_daily}'
UNION ALL
SELECT 'previous_record' as table_name, count(*) as row_count 
FROM {historic_schema_yearly}.ai_daily
WHERE run_id = '{previous_ai_customer}';

-- Test 2: Check for common ai_codes
-- WITH
-- latest_record AS (
--     SELECT ai_code FROM {historic_schema_yearly}.ai_daily
--     WHERE run_id = '{current_ai_daily}'
-- ),
-- previous_record AS (
--     SELECT ai_code FROM {historic_schema_yearly}.ai_daily
--     WHERE run_id = '{previous_ai_customer}'
-- )
-- SELECT 
--     'common_ai_codes' as test_name,
--     count(*) as count
-- FROM latest_record lr 
-- JOIN previous_record pr ON lr.ai_code = pr.ai_code;
