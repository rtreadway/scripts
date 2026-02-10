create table #aistoj as 
SELECT curr.*
FROM #curr curr
JOIN #prev prev ON curr.ai_code = prev.ai_code
WHERE prev.school_level = 'S' AND curr.school_level = 'J'