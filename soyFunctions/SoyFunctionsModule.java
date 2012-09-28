package gnewpg;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import com.google.inject.AbstractModule;
import com.google.inject.multibindings.Multibinder;
import com.google.template.soy.shared.restricted.SoyFunction;
import com.google.template.soy.jssrc.restricted.SoyJsSrcFunction;
import com.google.template.soy.jssrc.restricted.JsExpr;

/**
 * This adds the several functions to the soy template language.
 *
 * How this works is decribed on {@link "https://groups.google.com/d/msg/closure-templates-discuss/Fewbk_m1i2c/nSv5dO3W2-AJ"}.
 * 
 * The functions simply map themselves to the $ij.function(), where <code>function</code> is the function name. This is necessary because
 * soy does not allow calling methods directly. Those methods are injected into soy in the i18n.js file.
 *
 * As the $ij variable is normally not available if it is not explicitly used in the template, it is necessary to add the 
 * --isUsingIjData option to the soy template compiler. This is done in the server.js file, where this soy plugin is also
 * loaded into the compiler.
*/

public class SoyFunctionsModule extends AbstractModule
{
	@Override public void configure() {
		Multibinder<SoyFunction> soyFunctionsSetBinder = Multibinder.newSetBinder(binder(), SoyFunction.class);
		soyFunctionsSetBinder.addBinding().to(gettext.class);
		soyFunctionsSetBinder.addBinding().to(_.class);
		soyFunctionsSetBinder.addBinding().to(ngettext.class);
		soyFunctionsSetBinder.addBinding().to(mdgettext.class);
		soyFunctionsSetBinder.addBinding().to(formatFingerprint.class);
		soyFunctionsSetBinder.addBinding().to(formatKeyId.class);
	}

	public static class gettext implements SoyJsSrcFunction
	{
		private static Set<Integer> argsSizes = new HashSet<Integer>(Arrays.asList(new Integer[]{ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25 }));

		protected String name = "gettext";

		@Override public String getName() {
			return name;
		}

		@Override public Set<Integer> getValidArgsSizes() {
			return argsSizes;
		}

		@Override public JsExpr computeForJsSrc(List<JsExpr> args) {
			StringBuilder ret = new StringBuilder("opt_ijData.").append(name).append("(");
			boolean first = true;
			for(JsExpr arg : args)
			{
				if(first)
					first = false;
				else
					ret.append(", ");
				ret.append(arg.getText());
			}
			ret.append(")");
			
			return new JsExpr(ret.toString(), Integer.MAX_VALUE);
		}
	}
	
	public static class _ extends gettext
	{
		{ name = "_"; }
	}
	
	public static class ngettext extends gettext
	{
		{ name = "ngettext"; }
	}
	
	public static class mdgettext extends gettext
	{
		{ name = "mdgettext"; }
	}
	
	public static class formatFingerprint extends gettext
	{
		{ name = "formatFingerprint"; }
	}
	
	public static class formatKeyId extends gettext
	{
		{ name = "formatKeyId"; }
	}
}