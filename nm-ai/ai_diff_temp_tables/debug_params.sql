-- Debug version of ai_diffs.sql with explicit logging
-- First, let's verify the parameters are being substituted correctly

-- Test 1: Show what parameters we received
SELECT 
    '{historic_schema_yearly}' as historic_schema_yearly,
    '{current_ai_daily}' as current_ai_daily,
    '{previous_ai_customer}' as previous_ai_customer;

-- Test 2: Verify both source tables have data
-- SELECT 'latest_record' as table_name, count(*) as row_count 
-- FROM {historic_schema_yearly}.ai_daily
-- WHERE run_id = '{current_ai_daily}'
-- UNION ALL
-- SELECT 'previous_record' as table_name, count(*) as row_count 
-- FROM {historic_schema_yearly}.ai_daily
-- WHERE run_id = '{previous_ai_customer}';

-- Test 3: Simple diff test on just one field
-- WITH
-- latest_record AS (
--     SELECT ai_code, address_city FROM {historic_schema_yearly}.ai_daily
--     WHERE run_id = '{current_ai_daily}'
-- ),
-- previous_record AS (
--     SELECT ai_code, address_city FROM {historic_schema_yearly}.ai_daily
--     WHERE run_id = '{previous_ai_customer}'
-- )
-- SELECT 
--     lr.ai_code,
--     COALESCE(pr.address_city,'-') AS old_value,
--     COALESCE(lr.address_city,'-') AS new_value
-- FROM latest_record lr 
-- JOIN previous_record pr ON lr.ai_code = pr.ai_code
-- WHERE COALESCE(pr.address_city,'-') <> COALESCE(lr.address_city,'-')
-- LIMIT 10;
