create table #aijtos as 
SELECT curr.*
FROM #curr curr
JOIN #prev prev ON curr.ai_code = prev.ai_code
WHERE prev.school_level = 'J' AND curr.school_level = 'S'