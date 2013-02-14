$(document).ready(function() {
	$(".table-checkbox tbody tr:has(:checked)").addClass("success");

	$(".table-checkbox tbody td").click(function(e) {
		if($(e.target).is("a,a *"))
			return;

		var tr = $(this).parent();
		tr.toggleClass("success");
		$("input[type=checkbox]", tr).prop("checked", tr.hasClass("success"));
	});
});

function quoteRegexp(str) {
	return (str+'').replace(/([.?*+^$[\]\\(){}|-])/g, "\\$1");
}