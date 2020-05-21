//var filename = getFileName();
var port = window.location.port;
var filename='./data.json'

function getFileName(){
	var url = window.location.search;
	var regEx = /[?&]filename=([^&]*)/g;
	return regEx.exec(url)[1];
}


var width = 1000,
	height ;

var cluster;
var diagonal;
var svg;

function initChart()
{	
	cluster = d3.layout.cluster()
		.size([height,width - 160]);
	diagonal = d3.svg.diagonal()
		.projection(function(d) { return[d.y,d.x]; });
	svg = d3.select("body").append("svg")
		.attr("width",width)
		.attr("height",height)
	.append("g")
		.attr("transform","translate(70,0)");
}

function getSrcMatches(data){
	var src_matches =[];
	for (var i = 0; i < data.length; i++)
	{
		var elem = data[i];
		if(!checkForMatch(src_matches,elem.src_ip))
		{
			src_matches.push(elem.src_ip);
		}
	}
	return src_matches;
}

function getDstMatches(data, src_ip)
{
	var dest = [];
	for (var i = 0; i < data.length; i++)
	{
		var elem = data[i];
		if( elem.host == null || elem.host == "" )
		{
			name = elem.dst_ip;
		}
		else
		{
			name = elem.host;
		}
		
		if(!checkForMatch(dest,name))
		{
			dest.push(
			{
				name:name,
				src_ip:elem.src_ip,
				dst_ip:elem.dst_ip,
				src_mac:elem.src_mac,
				dst_mac:elem.dst_mac,
				time:elem.time,
				size:100
			});
		}
	}
	return dest;
}

function fixdata(data)
{	
	var children =[];
	var src = getSrcMatches(data);	
	for(var i =0;i < src.length; i++)
	{
		var dst = getDstMatches(data,src[i]);
		children.push({
			name:src[i],
			children:dst,
			size:100
		});		
	}
	var connections = {
		name:"Connections",
		children:children
		};
	return connections;
}

function checkForMatch(list, term)
{
	var isFound = false;
	if(list.length)
	{
		for(var i=0;i < list.length; i++)
		{
			if(!list[i].name)
			{
				if(list[i] == term)
				{
					return true;
				}
			}
			else
			{
				if(list[i].name == term)
				{
					return true;
				}
			}
		}
	}
	return false;
}

d3.json("http://localhost:"+port+"/"+filename, function(error, root)
{
	if (error) throw error;
	
	if(root.length < 10 )
	{
		height = 300;
	}
	else if(root.length < 50 )
	{
		height = 1000;
	}
	else if(root.length < 500 )
	{
		height = 2000;
	}
	else
	{
		height = 2 * root.length;
	}
	
	initChart();
	
	var data = fixdata(root);
	//alert(data);
	//alert(filename );
	
	var nodes = cluster.nodes(data),links = cluster.links(nodes);
	
	var link = svg.selectAll(".link")
		.data(links)
	.enter().append("path")
		.attr("class","link")
		.attr("d",diagonal)
		.attr("fill", "none")
	    .attr("stroke", "#555")
	    .attr("stroke-opacity", 0.4)
	    .attr("stroke-width", 1.5)		
		;
	
	var node = svg.selectAll(".node")
		.data(nodes)
	.enter().append("g")
		.attr("class","node")
		.attr("transform",function(d){ return "translate("+d.y+","+d.x+")";});		
	
	node.append("circle")
		.attr("r",4.5);
	
	node.append("text")
		.attr("dx",function (d) { return d.children ? -8 : 8;})
		.attr("dy",3)
		.style("text-anchor",function(d) { return d.children ? "end" : "start"; })
		.text(function(d) { return d.name; });
					
	d3.select("body svg").attr("width","2000px");
	
	node.on("mouseover",function(d){
		d3.select("#overlay")
			.style("left", ( d.y - 200 ) + "px")
			.style("top", d.x + "px" )
			.select("#time")
			.text(d.time);	
		d3.select("#overlay")
			.select("#host")
			.text(d.name);
		d3.select("#overlay")
			.select("#src_ip")
			.text(d.src_ip);
		d3.select("#overlay")
			.select("#dst_ip")
			.text(d.dst_ip);
		d3.select("#overlay")
			.select("#src_mac")
			.text(d.src_mac);
		d3.select("#overlay")
			.select("#dst_mac")
			.text(d.dst_mac);	
		d3.select("#overlay").classed("hidden",false);
		})
		.on("mouseout",function(d) { d3.select("#overlay").classed("hidden",true);
		});
}
);

d3.select(self.frameElement).style("height",height + "px");