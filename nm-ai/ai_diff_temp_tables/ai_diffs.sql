create table #diffs as
    WITH
    latest_record AS (
        SELECT * FROM {historic_schema_yearly}.ai_daily
        WHERE run_id = '{current_ai_daily}'
    ),
    previous_record AS (
        SELECT * FROM {historic_schema_yearly}.ai_daily
        WHERE run_id = '{previous_ai_customer}'
    ),
    different_records AS (
        SELECT CAST('address_city'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.address_city,'-') AS old_value, COALESCE(lr.address_city,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.address_city,'-') <> COALESCE(lr.address_city,'-')
    UNION ALL
        SELECT CAST('address_line1'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.address_line1,'-') AS old_value, COALESCE(lr.address_line1,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.address_line1,'-') <> COALESCE(lr.address_line1,'-')
    UNION ALL
        SELECT CAST('address_line2'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.address_line2,'-') AS old_value, COALESCE(lr.address_line2,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.address_line2,'-') <> COALESCE(lr.address_line2,'-')
    UNION ALL
        SELECT CAST('address_state'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.address_state,'-') AS old_value, COALESCE(lr.address_state,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.address_state,'-') <> COALESCE(lr.address_state,'-')
    UNION ALL
        SELECT CAST('address_zip'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.address_zip,'-') AS old_value, COALESCE(lr.address_zip,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.address_zip,'-') <> COALESCE(lr.address_zip,'-')
    UNION ALL
        SELECT CAST('ai_state_code'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.ai_state_code,'-') AS old_value, COALESCE(lr.ai_state_code,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.ai_state_code,'-') <> COALESCE(lr.ai_state_code,'-')
    UNION ALL
        SELECT CAST('aicode_minor'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.aicode_minor,'-') AS old_value, COALESCE(lr.aicode_minor,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.aicode_minor,'-') <> COALESCE(lr.aicode_minor,'-')
    UNION ALL
        SELECT CAST('alt_test_day'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.alt_test_day,'-') AS old_value, COALESCE(lr.alt_test_day,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.alt_test_day,'-') <> COALESCE(lr.alt_test_day,'-')
    UNION ALL
        SELECT CAST('alt_test_month'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.alt_test_month,'-') AS old_value, COALESCE(lr.alt_test_month,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.alt_test_month,'-') <> COALESCE(lr.alt_test_month,'-')
    UNION ALL
        SELECT CAST('cb_region'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.cb_region,'-') AS old_value, COALESCE(lr.cb_region,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.cb_region,'-') <> COALESCE(lr.cb_region,'-')
    UNION ALL
        SELECT CAST('foreign_domestic'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.foreign_domestic,'-') AS old_value, COALESCE(lr.foreign_domestic,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.foreign_domestic,'-') <> COALESCE(lr.foreign_domestic,'-')
    UNION ALL
        SELECT CAST('form'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.form,'-') AS old_value, COALESCE(lr.form,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.form,'-') <> COALESCE(lr.form,'-')
    UNION ALL
        SELECT CAST('hs_state_code'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.hs_state_code,'-') AS old_value, COALESCE(lr.hs_state_code,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.hs_state_code,'-') <> COALESCE(lr.hs_state_code,'-')
    UNION ALL
        SELECT CAST('late_ontime'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.late_ontime,'-') AS old_value, COALESCE(lr.late_ontime,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.late_ontime,'-') <> COALESCE(lr.late_ontime,'-')
    UNION ALL
        SELECT CAST('location'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.location,'-') AS old_value, COALESCE(lr.location,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.location,'-') <> COALESCE(lr.location,'-')
    UNION ALL
        SELECT CAST('name'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.name,'-') AS old_value, COALESCE(lr.name,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.name,'-') <> COALESCE(lr.name,'-')
    UNION ALL
        SELECT CAST('num_minor'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.num_minor,'-') AS old_value, COALESCE(lr.num_minor,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.num_minor,'-') <> COALESCE(lr.num_minor,'-')
    UNION ALL
        SELECT CAST('num_test_given'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.num_test_given,'-') AS old_value, COALESCE(lr.num_test_given,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.num_test_given,'-') <> COALESCE(lr.num_test_given,'-')
    UNION ALL
        SELECT CAST('num_test_ord'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.num_test_ord,'-') AS old_value, COALESCE(lr.num_test_ord,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.num_test_ord,'-') <> COALESCE(lr.num_test_ord,'-')
    UNION ALL
        SELECT CAST('origin'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.origin,'-') AS old_value, COALESCE(lr.origin,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.origin,'-') <> COALESCE(lr.origin,'-')
    UNION ALL
        SELECT CAST('participation'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.participation,'-') AS old_value, COALESCE(lr.participation,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.participation,'-') <> COALESCE(lr.participation,'-')
    UNION ALL
        SELECT CAST('percent_going_college'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.percent_going_college,'-') AS old_value, COALESCE(lr.percent_going_college,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.percent_going_college,'-') <> COALESCE(lr.percent_going_college,'-')
    UNION ALL
        SELECT CAST('phone'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.phone,'-') AS old_value, COALESCE(lr.phone,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.phone,'-') <> COALESCE(lr.phone,'-')
    UNION ALL
        SELECT CAST('pn_address_city'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.pn_address_city,'-') AS old_value, COALESCE(lr.pn_address_city,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.pn_address_city,'-') <> COALESCE(lr.pn_address_city,'-')
    UNION ALL
        SELECT CAST('pn_address_line1'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.pn_address_line1,'-') AS old_value, COALESCE(lr.pn_address_line1,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.pn_address_line1,'-') <> COALESCE(lr.pn_address_line1,'-')
    UNION ALL
        SELECT CAST('pn_address_line2'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.pn_address_line2,'-') AS old_value, COALESCE(lr.pn_address_line2,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.pn_address_line2,'-') <> COALESCE(lr.pn_address_line2,'-')
    UNION ALL
        SELECT CAST('pn_address_state'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.pn_address_state,'-') AS old_value, COALESCE(lr.pn_address_state,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.pn_address_state,'-') <> COALESCE(lr.pn_address_state,'-')
    UNION ALL
        SELECT CAST('pn_address_zip'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.pn_address_zip,'-') AS old_value, COALESCE(lr.pn_address_zip,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.pn_address_zip,'-') <> COALESCE(lr.pn_address_zip,'-')
    UNION ALL
        SELECT CAST('pn_country'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.pn_country,'-') AS old_value, COALESCE(lr.pn_country,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.pn_country,'-') <> COALESCE(lr.pn_country,'-')
    UNION ALL
        SELECT CAST('school_level'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.school_level,'-') AS old_value, COALESCE(lr.school_level,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.school_level,'-') <> COALESCE(lr.school_level,'-')
    UNION ALL
        SELECT CAST('ship_address_city'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.ship_address_city,'-') AS old_value, COALESCE(lr.ship_address_city,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.ship_address_city,'-') <> COALESCE(lr.ship_address_city,'-')
    UNION ALL
        SELECT CAST('ship_address_line1'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.ship_address_line1,'-') AS old_value, COALESCE(lr.ship_address_line1,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.ship_address_line1,'-') <> COALESCE(lr.ship_address_line1,'-')
    UNION ALL
        SELECT CAST('ship_address_line2'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.ship_address_line2,'-') AS old_value, COALESCE(lr.ship_address_line2,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.ship_address_line2,'-') <> COALESCE(lr.ship_address_line2,'-')
    UNION ALL
        SELECT CAST('ship_address_state'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.ship_address_state,'-') AS old_value, COALESCE(lr.ship_address_state,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.ship_address_state,'-') <> COALESCE(lr.ship_address_state,'-')
    UNION ALL
        SELECT CAST('ship_address_zip'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.ship_address_zip,'-') AS old_value, COALESCE(lr.ship_address_zip,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.ship_address_zip,'-') <> COALESCE(lr.ship_address_zip,'-')
    UNION ALL
        SELECT CAST('ship_country'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.ship_country,'-') AS old_value, COALESCE(lr.ship_country,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.ship_country,'-') <> COALESCE(lr.ship_country,'-')
    UNION ALL
        SELECT CAST('sname'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.sname,'-') AS old_value, COALESCE(lr.sname,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.sname,'-') <> COALESCE(lr.sname,'-')
    UNION ALL
        SELECT CAST('test_given'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.test_given,'-') AS old_value, COALESCE(lr.test_given,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.test_given,'-') <> COALESCE(lr.test_given,'-')
    UNION ALL
        SELECT CAST('test_year'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.test_year,'-') AS old_value, COALESCE(lr.test_year,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.test_year,'-') <> COALESCE(lr.test_year,'-')
    UNION ALL
        SELECT CAST('total_tested_current'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.total_tested_current,'-') AS old_value, COALESCE(lr.total_tested_current,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.total_tested_current,'-') <> COALESCE(lr.total_tested_current,'-')
    UNION ALL
        SELECT CAST('total_tested_previous'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.total_tested_previous,'-') AS old_value, COALESCE(lr.total_tested_previous,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.total_tested_previous,'-') <> COALESCE(lr.total_tested_previous,'-')
    UNION ALL
        SELECT CAST('type'AS varchar) AS field_name, lr.ai_code AS ai_code, pr.run_id AS previous_run_id, COALESCE(pr.type,'-') AS old_value, COALESCE(lr.type,'-') AS new_value, lr.run_id AS latest_run_id
        FROM latest_record lr JOIN previous_record pr ON lr.ai_code = pr.ai_code
        WHERE COALESCE(pr.type,'-') <> COALESCE(lr.type,'-')
    )
    SELECT * FROM different_records;
