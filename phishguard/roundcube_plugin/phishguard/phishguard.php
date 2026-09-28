<?php
class phishguard extends rcube_plugin
{
    public $task = 'mail';

    function init()
    {
        $this->add_hook('message_headers_output', array($this, 'check_phishguard_headers'));
        $this->add_hook('message_body_prefix', array($this, 'show_phishguard_warning'));
    }

    function check_phishguard_headers($args)
    {
        // Add specific JS/CSS if needed
        return $args;
    }

    function show_phishguard_warning($args)
    {
        $rcmail = rcmail::get_instance();
        $message = $args['message'];
        $flags = $message->headers->flags;

        $is_flagged = false;
        if (isset($flags['$phishing']) || in_array('$phishing', $flags)) {
            $is_flagged = true;
        }

        if ($is_flagged) {
            $warning = '<div style="background-color: #fef2f2; border: 1px solid #ef4444; color: #b91c1c; padding: 1rem; margin-bottom: 1rem; border-radius: 0.375rem;">';
            $warning .= '<h3 style="margin-top: 0; font-size: 1.125rem; font-weight: bold;">⚠️ PhishGuard Warning</h3>';
            $warning .= '<p style="margin-bottom: 0;">This email has been flagged as suspicious by our security models. Please exercise extreme caution when clicking links or downloading attachments.</p>';
            $warning .= '</div>';
            
            $args['prefix'] = $warning . $args['prefix'];
        }

        return $args;
    }
}
?>
