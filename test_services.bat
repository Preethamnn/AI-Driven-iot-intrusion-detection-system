@echo off
echo Testing Elasticsearch and Kibana Services
echo ==========================================

echo.
echo Testing Elasticsearch on port 9200...
curl -s http://localhost:9200/_cluster/health
echo.

echo.
echo Testing Kibana on port 5601...
curl -s http://localhost:5601/api/status
echo.

echo.
echo Services Status:
echo - Elasticsearch: http://localhost:9200
echo - Kibana Dashboard: http://localhost:5601
echo.
pause