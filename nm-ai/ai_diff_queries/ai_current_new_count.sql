select count(*)
FROM #curr curr
LEFT join #prev prev
ON curr.AI_CODE = prev.AI_CODE
WHERE prev.AI_CODE IS NULL 