moved {
  from = azurerm_servicebus_queue_authorization_rule.q_send
  to   = azurerm_servicebus_queue_authorization_rule.queue_rule["q_send"]
}

moved {
  from = azurerm_servicebus_queue_authorization_rule.q_listen
  to   = azurerm_servicebus_queue_authorization_rule.queue_rule["q_listen"]
}

moved {
  from = azurerm_servicebus_queue_authorization_rule.q_manage
  to   = azurerm_servicebus_queue_authorization_rule.queue_rule["q_manage"]
}

moved {
  from = azurerm_servicebus_queue_authorization_rule.q_scan_send
  to   = azurerm_servicebus_queue_authorization_rule.queue_rule["q_scan_send"]
}

moved {
  from = azurerm_servicebus_queue_authorization_rule.q_scan_listen
  to   = azurerm_servicebus_queue_authorization_rule.queue_rule["q_scan_listen"]
}

moved {
  from = azurerm_servicebus_queue_authorization_rule.q_scan_manage
  to   = azurerm_servicebus_queue_authorization_rule.queue_rule["q_scan_manage"]
}

moved {
  from = azurerm_key_vault_secret.sb_send
  to   = azurerm_key_vault_secret.runtime["sb_send"]
}

moved {
  from = azurerm_key_vault_secret.sb_listen
  to   = azurerm_key_vault_secret.runtime["sb_listen"]
}

moved {
  from = azurerm_key_vault_secret.sb_manage
  to   = azurerm_key_vault_secret.runtime["sb_manage"]
}

moved {
  from = azurerm_key_vault_secret.sb_scan_send
  to   = azurerm_key_vault_secret.runtime["sb_scan_send"]
}

moved {
  from = azurerm_key_vault_secret.sb_scan_listen
  to   = azurerm_key_vault_secret.runtime["sb_scan_listen"]
}

moved {
  from = azurerm_key_vault_secret.sb_scan_manage
  to   = azurerm_key_vault_secret.runtime["sb_scan_manage"]
}

moved {
  from = azurerm_key_vault_secret.results_conn
  to   = azurerm_key_vault_secret.runtime["results_conn"]
}

moved {
  from = azurerm_key_vault_secret.webpubsub_conn
  to   = azurerm_key_vault_secret.runtime["webpubsub_conn"]
}

moved {
  from = azurerm_log_analytics_saved_search.api_5xx
  to   = azurerm_log_analytics_saved_search.saved_search["api_5xx"]
}

moved {
  from = azurerm_log_analytics_saved_search.pipeline_errors
  to   = azurerm_log_analytics_saved_search.saved_search["pipeline_errors"]
}

moved {
  from = azurerm_log_analytics_saved_search.queue_backlog
  to   = azurerm_log_analytics_saved_search.saved_search["queue_backlog"]
}

moved {
  from = azurerm_log_analytics_saved_search.deadletter_growth
  to   = azurerm_log_analytics_saved_search.saved_search["deadletter_growth"]
}

moved {
  from = azurerm_log_analytics_saved_search.stalled_pipeline
  to   = azurerm_log_analytics_saved_search.saved_search["stalled_pipeline"]
}

moved {
  from = azurerm_monitor_scheduled_query_rules_alert_v2.api_5xx[0]
  to   = azurerm_monitor_scheduled_query_rules_alert_v2.alert["api_5xx"]
}

moved {
  from = azurerm_monitor_scheduled_query_rules_alert_v2.pipeline_errors[0]
  to   = azurerm_monitor_scheduled_query_rules_alert_v2.alert["pipeline_errors"]
}

moved {
  from = azurerm_monitor_scheduled_query_rules_alert_v2.queue_backlog[0]
  to   = azurerm_monitor_scheduled_query_rules_alert_v2.alert["queue_backlog"]
}

moved {
  from = azurerm_monitor_scheduled_query_rules_alert_v2.deadletter_growth[0]
  to   = azurerm_monitor_scheduled_query_rules_alert_v2.alert["deadletter_growth"]
}

moved {
  from = azurerm_monitor_scheduled_query_rules_alert_v2.stalled_pipeline[0]
  to   = azurerm_monitor_scheduled_query_rules_alert_v2.alert["stalled_pipeline"]
}
