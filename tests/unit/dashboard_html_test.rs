use agentwall::dashboard::dashboard_html;

#[test]
fn test_dashboard_html_is_embedded() {
    let html = dashboard_html();
    assert!(!html.is_empty(), "Dashboard HTML should not be empty");
    assert!(html.contains("<!DOCTYPE html>"), "Dashboard HTML should contain doctype");
    assert!(html.contains("panel-inventory"), "Dashboard HTML should contain inventory view");
    assert!(html.contains("panel-timeline"), "Dashboard HTML should contain timeline view");
    assert!(html.contains("panel-params"), "Dashboard HTML should contain params view");
    assert!(html.contains("panel-risks"), "Dashboard HTML should contain risks view");
    assert!(html.contains("panel-policy"), "Dashboard HTML should contain policy view");
}
