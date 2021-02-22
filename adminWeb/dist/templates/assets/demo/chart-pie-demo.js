// Set new default font family and font color to mimic Bootstrap's default styling
Chart.defaults.global.defaultFontFamily = '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
Chart.defaults.global.defaultFontColor = '#22b2c';

// Pie Chart Example
var ctx = document.getElementById("myPieChart");
var myPieChart = new Chart(ctx, {
  type: 'pie',
  data: {
      labels: ["rejected", "handled successfully", "Other", ],
    datasets: [{
      data: [7.21, 15.25, 3.32],
      backgroundColor: ['#007bff', '#ffc107', '#28a745'],
    }],
  },
});
