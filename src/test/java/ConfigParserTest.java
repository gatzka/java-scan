import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.hbm.devices.configure.ConfigParser;
import com.hbm.devices.configure.Device;
import com.hbm.devices.configure.FakeMulticastSender;
import com.hbm.devices.configure.Interface;
import com.hbm.devices.configure.NetSettings;
import com.hbm.devices.configure.Noticeable;
import com.hbm.devices.scan.MissingDataException;
import com.hbm.devices.scan.messages.Configure;
import com.hbm.devices.scan.messages.ConfigureParams;
import com.hbm.devices.scan.messages.Interface.Method;

public class ConfigParserTest {

	private FakeMulticastSender fs;

	private ConfigParser cp;

	private JsonParser parser;

	private Exception exception;

	@Before
	public void setup() {
		fs = new FakeMulticastSender();

		cp = new ConfigParser(new Noticeable() {
			public void onException(Exception e) {
				exception = e;
			}
		});
		cp.addObserver(fs);

		parser = new JsonParser();

		this.exception = null;
	}

	@Test
	public void parseCorrectConfig() {
		Device device = new Device("0009E5001571");
		NetSettings settings = new NetSettings(new Interface("eth0", Method.dhcp, null));
		ConfigureParams configParams = new ConfigureParams(device, settings);
		Configure conf = new Configure(configParams, "TEST-UUID");

		cp.update(null, conf);
		String correctOutParsed = "{\"params\":{\"device\":{\"uuid\":\"0009E5001571\"},\"netSettings\":{\"interface\":{\"name\":\"eth0\",\"configurationMethod\":\"dhcp\"}},\"ttl\":1},\"id\":\"TEST-UUID\",\"jsonrpc\":\"2.0\",\"method\":\"configure\"}";
		JsonElement correct = parser.parse(correctOutParsed);
		JsonElement sent = parser.parse(fs.getLastSent());
		assertTrue(sent.equals(correct));
	}

	@Test
	public void parseNullConfigure() {
		cp.update(null, null);
		assertTrue(this.exception instanceof NullPointerException);
	}

	@Test
	public void parseNullParams() {
		Configure conf = new Configure(null, "TEST-UUID");
		cp.update(null, conf);
		assertTrue(this.exception instanceof NullPointerException);
	}

	@Test
	public void parseNullUUID() {
		Device device = new Device("0009E5001571");
		NetSettings settings = new NetSettings(new Interface("eth0", Method.dhcp, null));
		ConfigureParams configParams = new ConfigureParams(device, settings);
		Configure conf = new Configure(configParams, null);
		cp.update(null, conf);
		assertTrue(this.exception instanceof NullPointerException);
	}

	@Test
	public void parseNullDevice() {
		NetSettings settings = new NetSettings(new Interface("eth0", Method.dhcp, null));
		ConfigureParams configParams = new ConfigureParams(null, settings);
		Configure conf = new Configure(configParams, "TEST-UUID");
		cp.update(null, conf);
		assertTrue(this.exception instanceof NullPointerException);
	}

	@Test
	public void parseNoDevice() {
		Device device = new Device("");
		NetSettings settings = new NetSettings(new Interface("eth0", Method.dhcp, null));
		ConfigureParams configParams = new ConfigureParams(device, settings);
		Configure conf = new Configure(configParams, "TEST-UUID");
		cp.update(null, conf);
		assertTrue(fs.getLastSent() == null);
		assertTrue(this.exception instanceof MissingDataException);
	}

	@Test
	public void parseNullNetSettings() {
		Device device = new Device("0009E5001571");
		ConfigureParams configParams = new ConfigureParams(device, null);
		Configure conf = new Configure(configParams, null);
		cp.update(null, conf);
		assertTrue(this.exception instanceof NullPointerException);
	}

	@Test
	public void parseNullInterface() {
		Device device = new Device("0009E5001571");
		NetSettings settings = new NetSettings(null);
		ConfigureParams configParams = new ConfigureParams(device, settings);
		Configure conf = new Configure(configParams, "TEST-UUID");
		cp.update(null, conf);
		assertTrue(this.exception instanceof NullPointerException);
	}

	@Test
	public void parseNullInterfaceName() {
		Device device = new Device("0009E5001571");
		NetSettings settings = new NetSettings(new Interface(null, Method.dhcp, null));
		ConfigureParams configParams = new ConfigureParams(device, settings);
		Configure conf = new Configure(configParams, "TEST-UUID");
		cp.update(null, conf);
		assertTrue(this.exception instanceof NullPointerException);
	}

	@Test
	public void parseNoInterfaceName() {
		Device device = new Device("0009E5001571");
		NetSettings settings = new NetSettings(new Interface("", Method.dhcp, null));
		ConfigureParams configParams = new ConfigureParams(device, settings);
		Configure conf = new Configure(configParams, "TEST-UUID");
		cp.update(null, conf);
		assertTrue(fs.getLastSent() == null);
		assertTrue(this.exception instanceof MissingDataException);
	}

	@Test
	public void parseNoConfigurationMethod() {
		Device device = new Device("0009E5001571");
		NetSettings settings = new NetSettings(new Interface("eth0", null, null));
		ConfigureParams configParams = new ConfigureParams(device, settings);
		Configure conf = new Configure(configParams, "TEST-UUID");
		cp.update(null, conf);
		assertTrue(this.exception instanceof MissingDataException);
	}

	@Test
	public void parseManualAndNoIp() {
		Device device = new Device("0009E5001571");
		NetSettings settings = new NetSettings(new Interface("eth0", Method.manual, null));
		ConfigureParams configParams = new ConfigureParams(device, settings);
		Configure conf = new Configure(configParams, "TEST-UUID");
		cp.update(null, conf);
		assertTrue(this.exception instanceof MissingDataException);
	}

}