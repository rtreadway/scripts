SELECT 
distinct aaf.ai, 
prev.*
FROM #prev prev
LEFT join #curr curr
	ON curr.AI_CODE = prev.AI_CODE
left join team_rp__nm_current_all.ai_all_fields aaf on aaf.ai_cd = prev.ai_code
WHERE curr.AI_CODE IS NULL 
ORDER BY prev.AI_CODE ;