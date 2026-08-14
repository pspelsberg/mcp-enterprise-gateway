from src.server import _anonymize_prompt, _execute_docker_code

def test_tool_contract():
    result=_anonymize_prompt("mail a@example.com")
    assert result["pii_count"]==1
    assert "session_id" in result

def test_invalid_tool_input_is_not_executed():
    result=_execute_docker_code("x","ruby",10)
    assert result["error"]["code"]=="validation_error"
