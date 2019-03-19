from ntp2chrony import ntp2chrony

NTP_CONF = "tests/data/ntp.conf"
STEP_TICKERS = "tests/data/step_tickers"


class TestConverter(object):
    def test_basic(self):
        config = ntp2chrony.NtpConfiguration('', NTP_CONF, step_tickers=STEP_TICKERS)
        present = [config.restrictions, config.driftfile, config.trusted_keys, config.keys,
                   config.step_tickers, config.restrictions]
        for section in present:
            assert section
        chrony_conf = config.get_chrony_conf('/etc/chrony.keys')
        # additional verification section by section for each param in present?

        # verify step_tickers -> initstepslew
        initstepslew_line = next((l for l in chrony_conf.split('\n')
                                  if l.startswith('initstepslew')), None)
        assert initstepslew_line and initstepslew_line.endswith(' '.join(config.step_tickers))
        chrony_keys = config.get_chrony_keys()
        # verify keys generation
        for num, _, key in config.keys:
            expected = ('%(num)s MD5 %(key)s' %
                        {'key': 'HEX:' if len(key) > 20 else 'ASCII:' + key, 'num': num})
            # keys not from trusted keys are commented out by default
            if not any(num in range(x, y+1) for (x, y) in config.trusted_keys):
                expected = '#' + expected
            assert expected in chrony_keys
