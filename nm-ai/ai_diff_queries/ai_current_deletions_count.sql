SELECT count(*)
FROM #prev prev
LEFT join #curr curr
	ON curr.AI_CODE = prev.AI_CODE
WHERE curr.AI_CODE IS NULL 