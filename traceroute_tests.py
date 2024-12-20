import struct
import unittest
from unittest.mock import patch, MagicMock, mock_open
import socket
import sys
from io import StringIO
from traceroute import Traceroute, parse_args


class TestParseArgs(unittest.TestCase):
    def test_default_args(self):
        test_args = ['destination.com']
        with patch.object(sys, 'argv', ['prog'] + test_args):
            args = parse_args()
            self.assertEqual(args.destination, 'destination.com')
            self.assertEqual(args.bytes, 40)
            self.assertEqual(args.max_hops, 64)
            self.assertEqual(args.timeout, 2)
            self.assertEqual(args.interval, 0)
            self.assertFalse(args.debug_mode)

    def test_custom_args(self):
        test_args = ['destination.com', '-b', '100', '-m', '30', '-t', '1', '-i', '0.5', '-d']
        with patch.object(sys, 'argv', ['prog'] + test_args):
            args = parse_args()
            self.assertEqual(args.bytes, 100)
            self.assertEqual(args.max_hops, 30)
            self.assertEqual(args.timeout, 1)
            self.assertEqual(args.interval, 0.5)
            self.assertTrue(args.debug_mode)


class TestParseTypes(unittest.TestCase):
    def test_parse_types(self):
        file_content = "0 echo_reply\n8 echo"
        with patch('builtins.open', mock_open(read_data=file_content)):
            t = Traceroute('localhost', 40, 64, 2, 0, False)
            self.assertEqual(t.response_codes[0], 'echo_reply')
            self.assertEqual(t.response_codes[8], 'echo')
            self.assertEqual(t.response_codes[1], 'reserved code or not existed')


class TestCraftICMP(unittest.TestCase):
    def test_craft_icmp(self):
        t = Traceroute('localhost', 40, 64, 2, 0, False)
        seq = 1
        packet = t.craft_icmp(seq)
        self.assertTrue(len(packet) == (8 + 40))
        self.assertEqual(packet[0], 8)


class TestSendPacket(unittest.TestCase):
    @patch('socket.socket')
    def test_send_packet(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        t = Traceroute('localhost', 40, 64, 2, 0, False)
        seq = 1
        start_time = t.send_packet(seq)
        self.assertIsNotNone(start_time)
        mock_socket.sendto.assert_called_once()


class TestParseReply(unittest.TestCase):
    @patch('socket.socket')
    def test_parse_reply_success(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        # Имитация получения ответа
        mock_socket.recvfrom.return_value = (b'\x45\x00', ('1.1.1.1', 0))
        t = Traceroute('localhost', 40, 64, 2, 0, False)
        packet = t.parse_reply(ttl=1, seq=1)
        self.assertEqual(packet, b'\x45\x00')

    @patch('socket.socket')
    def test_parse_reply_timeout(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.recvfrom.side_effect = socket.timeout
        t = Traceroute('localhost', 40, 64, 0.1, 0, False)
        captured_output = StringIO()
        with patch('sys.stdout', new=captured_output):
            packet = t.parse_reply(ttl=1, seq=1)
        self.assertIsNone(packet)
        self.assertIn('*', captured_output.getvalue())


class TestTryFindHost(unittest.TestCase):
    @patch('socket.gethostbyname', return_value='8.8.8.8')
    def test_try_find_host_success(self, mock_gethostbyname):
        t = Traceroute('google.com', 40, 64, 2, 0, False)
        captured_output = StringIO()
        with patch('sys.stdout', new=captured_output):
            t.try_find_host()
        self.assertIn('traceroute to google.com (8.8.8.8)', captured_output.getvalue())

    @patch('socket.gethostbyname', side_effect=socket.gaierror)
    def test_try_find_host_failure(self, mock_gethostbyname):
        t = Traceroute('unknownhost', 40, 64, 2, 0, False)
        captured_output = StringIO()
        with patch('sys.stdout', new=captured_output):
            try:
                t.try_find_host()
            except socket.gaierror:
                pass
        self.assertNotIn('traceroute to', captured_output.getvalue())


class TestTracerouteIntegration(unittest.TestCase):
    @patch('socket.gethostbyname', return_value='8.8.8.8')
    @patch('socket.gethostbyaddr', return_value=('example.com', [], ['8.8.8.8']))
    @patch('socket.socket')
    def test_traceroute_flow(self, mock_socket_class, mock_gethostbyaddr, mock_gethostbyname):
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        ip_header = struct.pack("!BBHHHBBHII", 69, 0, 84, 0, 0, 64, 1, 0, 134744072, 0)
        icmp_header = struct.pack("!BBHHH", 0, 0, 0, 0, 0)
        echo_reply_packet = ip_header + icmp_header

        mock_socket.recvfrom.return_value = (echo_reply_packet, ('8.8.8.8', 0))

        file_content = "0 echo_reply\n8 echo"
        with patch('builtins.open', mock_open(read_data=file_content)):
            t = Traceroute('google.com', 40, 1, 2, 0, False)
            captured_output = StringIO()
            with patch('sys.stdout', new=captured_output):
                t.traceroute()

        output = captured_output.getvalue()
        self.assertIn('traceroute to google.com (8.8.8.8)', output)

    @patch('socket.socket')
    @patch('socket.gethostbyaddr')
    @patch('socket.gethostbyname')
    def test_traceroute_no_reply(self, mock_gethostbyname, mock_gethostbyaddr, mock_socket_class):
        mock_gethostbyname.return_value = '8.8.4.4'
        mock_gethostbyaddr.return_value = ('dns.google', [], ['8.8.4.4'])

        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.recvfrom.side_effect = socket.timeout

        file_content = "0 echo_reply\n8 echo"
        with patch('builtins.open', mock_open(read_data=file_content)):
            t = Traceroute(destination='google.com',
                           packet_count_bytes=40,
                           max_hops=2,
                           timeout=1,
                           interval=0,
                           debug_mode=False)

            captured_output = StringIO()
            with patch('sys.stdout', new=captured_output):
                t.traceroute()

        output = captured_output.getvalue()

        expected_start = 'traceroute to google.com (8.8.4.4), 2 hops max, 40 byte packets'
        self.assertIn(expected_start, output)

        self.assertIn('1   * * *', output)
        self.assertIn('2   * * *', output)

        mock_socket.setsockopt.assert_any_call(socket.SOL_IP, socket.IP_TTL, 1)
        mock_socket.setsockopt.assert_any_call(socket.SOL_IP, socket.IP_TTL, 2)
        self.assertEqual(mock_socket.sendto.call_count, 6)
        self.assertEqual(mock_socket.recvfrom.call_count, 6)


if __name__ == '__main__':
    unittest.main()
